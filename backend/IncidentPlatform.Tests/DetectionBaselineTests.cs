using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class DetectionBaselineTests
{
    private static DetectionRule Rule(string severity, string? service, string? category = null, string status = "Compiled", string? externalId = null)
    {
        var source = service is not null
            ? $"\"service\":\"{service}\""
            : $"\"category\":\"{category}\"";
        var json = $"{{\"compilerVersion\":1,\"status\":\"{status}\",\"logsource\":{{\"product\":\"windows\",{source}}}," +
                   "\"compiled\":{\"op\":\"field\",\"field\":\"EventID\",\"value\":{\"kind\":\"number\",\"value\":4625}},\"tags\":[]}";
        return new DetectionRule { ExternalRuleId = externalId ?? Guid.NewGuid().ToString(), Title = "t", Severity = severity, DefinitionJson = json };
    }

    [Fact]
    public void Recommended_requires_support_collected_channel_and_high_severity()
    {
        Assert.True(DetectionBaseline.IsRecommended(Rule("High", "security")));
        Assert.True(DetectionBaseline.IsRecommended(Rule("Critical", "windefend")));
        Assert.True(DetectionBaseline.IsRecommended(Rule("High", "powershell")));

        Assert.False(DetectionBaseline.IsRecommended(Rule("Medium", "security")));           // not high enough
        Assert.False(DetectionBaseline.IsRecommended(Rule("High", service: null, category: "process_creation"))); // Sysmon-only; no channel
        Assert.False(DetectionBaseline.IsRecommended(Rule("High", "security", status: "Error"))); // not compiled / unsupported
    }

    [Fact]
    public void Denylisted_noise_is_never_recommended_even_when_otherwise_valid()
    {
        var logoff = Rule("High", "security", externalId: DetectionBaseline.NoiseDenylist[0]);
        Assert.True(DetectionBaseline.IsNoise(logoff.ExternalRuleId));
        Assert.False(DetectionBaseline.IsRecommended(logoff));
    }

    [Fact]
    public void Service_is_null_for_category_based_rules()
    {
        Assert.Equal("security", DetectionBaseline.Service(Rule("High", "security")));
        Assert.Null(DetectionBaseline.Service(Rule("High", service: null, category: "network_connection")));
    }
}

public class DetectionBaselineApiTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public DetectionBaselineApiTests(TestApiFactory factory) => _factory = factory;

    private async Task<(string Email, int Id)> UserAsync(string role)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();
        var email = $"base-{Guid.NewGuid():N}@example.com";
        var user = new User { Email = email, FullName = "Baseline Tester", PasswordHash = hasher.Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var r = await db.Roles.SingleAsync(x => x.Name == role);
        db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = r.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
        await db.SaveChangesAsync();
        return (email, user.Id);
    }

    private async Task<HttpClient> ClientAsync(string email)
    {
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.AccessToken);
        return client;
    }

    [Fact]
    public async Task Apply_enables_recommended_rules_and_suppresses_denylisted_noise()
    {
        const string supportedDef =
            "{\"compilerVersion\":1,\"status\":\"Compiled\",\"logsource\":{\"product\":\"windows\",\"service\":\"security\"}," +
            "\"compiled\":{\"op\":\"field\",\"field\":\"EventID\",\"value\":{\"kind\":\"number\",\"value\":4625}},\"tags\":[]}";
        var good = Guid.NewGuid().ToString();
        var logoff = DetectionBaseline.NoiseDenylist[0];
        var (adminEmail, adminId) = await UserAsync(RoleNames.Admin);
        var (managerEmail, _) = await UserAsync(RoleNames.SecurityManager);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            // Make sure a prior run's denylisted rule is gone (unique external id).
            await db.DetectionRules.Where(r => r.ExternalRuleId == logoff || r.ExternalRuleId == good).ExecuteDeleteAsync();
            db.DetectionRules.Add(new DetectionRule { ExternalRuleId = good, Title = "Failed logons (brute force)", Severity = "High", DefinitionJson = supportedDef, Enabled = false, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
            db.DetectionRules.Add(new DetectionRule { ExternalRuleId = logoff, Title = "User Logoff Event", Severity = "Informational", DefinitionJson = supportedDef, Enabled = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
            db.Alerts.Add(new Alert { Title = "User Logoff Event", Source = AlertSource.WindowsEvent, SourceRuleId = "SIGMA-" + logoff, DeduplicationKey = "sigma:" + logoff + ":" + Guid.NewGuid().ToString("N"), Severity = "Informational", Status = AlertStatus.New, DetectedAt = DateTime.UtcNow, ReceivedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        try
        {
            var admin = await ClientAsync(adminEmail);
            var before = await admin.GetFromJsonAsync<JsonElementLike>("/api/detection-rules/baseline");
            Assert.True(before!.recommendedDisabled >= 1);
            Assert.True(before.noisyEnabled >= 1);

            // Manager can view but not apply.
            var manager = await ClientAsync(managerEmail);
            Assert.Equal(HttpStatusCode.OK, (await manager.GetAsync("/api/detection-rules/baseline")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await manager.PostAsJsonAsync("/api/detection-rules/baseline/apply", new { confirmed = true })).StatusCode);

            // Unconfirmed is rejected.
            Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/api/detection-rules/baseline/apply", new { confirmed = false })).StatusCode);

            var applied = await (await admin.PostAsJsonAsync("/api/detection-rules/baseline/apply", new { confirmed = true })).Content.ReadFromJsonAsync<ApplyResult>();
            Assert.True(applied!.enabled >= 1);
            Assert.True(applied.disabled >= 1);
            Assert.True(applied.alertsSuppressed >= 1);

            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.True(await db.DetectionRules.AnyAsync(r => r.ExternalRuleId == good && r.Enabled));
            Assert.Equal("Observe", (await db.AutomationRules.SingleAsync(p => p.Id == "SIGMA-" + good)).Mode);
            Assert.False(await db.DetectionRules.AnyAsync(r => r.ExternalRuleId == logoff && r.Enabled));
            Assert.False(await db.Alerts.AnyAsync(a => a.SourceRuleId == "SIGMA-" + logoff && a.Status == AlertStatus.New));
        }
        finally
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Alerts.Where(a => a.SourceRuleId == "SIGMA-" + logoff || a.SourceRuleId == "SIGMA-" + good).ExecuteDeleteAsync();
            await db.AutomationRules.Where(p => p.Id == "SIGMA-" + logoff || p.Id == "SIGMA-" + good).ExecuteDeleteAsync();
            await db.DetectionRules.Where(r => r.ExternalRuleId == logoff || r.ExternalRuleId == good).ExecuteDeleteAsync();
            await db.AuditLogs.Where(a => a.Action == "DETECTION_BASELINE_APPLIED" && a.ActorUserId == adminId).ExecuteDeleteAsync();
            foreach (var email in new[] { adminEmail, managerEmail })
            {
                var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);
                if (user is null) continue;
                db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
                db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id));
                db.AuditLogs.RemoveRange(db.AuditLogs.Where(a => a.ActorUserId == user.Id || a.ActorEmail == email));
                db.Users.Remove(user);
                await db.SaveChangesAsync();
            }
        }
    }

    private sealed record JsonElementLike(int recommendedTotal, int recommendedEnabled, int recommendedDisabled, int noisyEnabled, int enabledTotal);
    private sealed record ApplyResult(int recommendedTotal, int enabled, int alreadyEnabled, int disabled, int alertsSuppressed);
}
