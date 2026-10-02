using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Logs;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class LogIngestionTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public LogIngestionTests(TestApiFactory factory) => _factory = factory;

    private const string IngestKey = "test-ingest-key-0001";

    private HttpClient IngestClient()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Ingest-Key", IngestKey);
        return client;
    }

    private async Task<(string Email, HttpClient Client)> ManagerClientAsync()
    {
        string email;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();
            email = $"logtest-{Guid.NewGuid():N}@example.com";
            var user = new User { Email = email, FullName = "Log Tester", PasswordHash = hasher.Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            var role = await db.Roles.SingleAsync(r => r.Name == RoleNames.SecurityManager);
            db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
            await db.SaveChangesAsync();
        }
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.AccessToken);
        return (email, client);
    }

    [Fact]
    public async Task Ingest_parses_normalizes_deduplicates_and_alerts_on_vpn_failures()
    {
        var source = $"vpn-{Guid.NewGuid():N}"[..20];
        var started = DateTime.UtcNow;
        var (email, manager) = await ManagerClientAsync();
        try
        {
            var batch = new IngestRequest
            {
                Source = source,
                Format = LogFormat.Vpn,
                Lines =
                [
                    "<38>Oct  2 03:04:05 vpn1 vpnd: user=alice action=login outcome=failure src=203.0.113.9",
                    "<38>Oct  2 03:04:06 vpn1 vpnd: user=bob action=login outcome=failure src=203.0.113.10",
                    "<38>Oct  2 03:04:07 vpn1 vpnd: user=carol action=login outcome=success src=203.0.113.11",
                    "   "
                ]
            };

            var first = await IngestClient().PostAsJsonAsync("/api/logs/ingest", batch);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            var result = await first.Content.ReadFromJsonAsync<IngestResponse>();
            Assert.Equal(3, result!.Accepted);
            Assert.Equal(1, result.Blank);
            Assert.Equal(2, result.Alerts);       // two distinct failed logins

            // Re-sending the same batch stores nothing new.
            var again = await (await IngestClient().PostAsJsonAsync("/api/logs/ingest", batch)).Content.ReadFromJsonAsync<IngestResponse>();
            Assert.Equal(0, again!.Accepted);
            Assert.Equal(3, again.Duplicates);

            // Analyst query: the two alerting events are visible with an alert id.
            var alerting = await manager.GetFromJsonAsync<PagedResult<LogSummaryResponse>>(
                $"/api/logs?source={source}&sourceType=Vpn&alertsOnly=true");
            Assert.Equal(2, alerting!.Items.Count);
            Assert.All(alerting.Items, e => Assert.NotNull(e.AlertId));
            Assert.All(alerting.Items, e => Assert.Equal("failure", e.Outcome));

            // The alerts reached the normal pipeline.
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var alertCount = await db.Alerts.CountAsync(a => a.Source == AlertSource.Vpn && a.ReceivedAt >= started);
            Assert.Equal(2, alertCount);
        }
        finally { await CleanupAsync(source, started, email); }
    }

    [Fact]
    public async Task Ingest_enriches_against_malicious_iocs_and_raises_a_high_alert()
    {
        var source = $"fw-{Guid.NewGuid():N}"[..20];
        var started = DateTime.UtcNow;
        var badIp = "198.51.100.7";
        var (email, manager) = await ManagerClientAsync();
        int iocId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var creatorId = await db.Users.Where(u => u.Email == email).Select(u => u.Id).SingleAsync();
            var ioc = new Ioc { Type = IocType.IpAddress, Value = badIp, IsMalicious = true, Confidence = IocConfidence.High, CreatedById = creatorId, FirstSeenAt = DateTime.UtcNow, LastSeenAt = DateTime.UtcNow };
            db.Iocs.Add(ioc);
            await db.SaveChangesAsync();
            iocId = ioc.Id;
        }
        try
        {
            var batch = new IngestRequest
            {
                Source = source,
                Format = LogFormat.Firewall,
                Lines = [$"<38>Oct  2 03:04:05 fw1 fw: src=10.0.0.5 dst={badIp} spt=51000 dpt=443 proto=tcp action=allow"]
            };
            var result = await (await IngestClient().PostAsJsonAsync("/api/logs/ingest", batch)).Content.ReadFromJsonAsync<IngestResponse>();
            Assert.Equal(1, result!.Accepted);
            Assert.Equal(1, result.Alerts);

            var page = await manager.GetFromJsonAsync<PagedResult<LogSummaryResponse>>($"/api/logs?source={source}");
            var row = Assert.Single(page!.Items);
            Assert.True(row.Enriched);

            var detail = await manager.GetFromJsonAsync<LogDetailResponse>($"/api/logs/{row.Id}");
            Assert.Contains(badIp, detail!.EnrichmentJson);

            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.True(await db.Alerts.AnyAsync(a => a.SourceRuleId == "LOG-IOC-MATCH" && a.ReceivedAt >= started && a.Severity == "High"));
        }
        finally
        {
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                await db.Iocs.Where(i => i.Id == iocId).ExecuteDeleteAsync();
            }
            await CleanupAsync(source, started, email);
        }
    }

    [Fact]
    public async Task Ingest_rejects_missing_key_and_query_rejects_bad_sort()
    {
        var (email, manager) = await ManagerClientAsync();
        try
        {
            var noKey = _factory.CreateClient();
            var rejected = await noKey.PostAsJsonAsync("/api/logs/ingest",
                new IngestRequest { Source = "x", Format = LogFormat.Syslog, Lines = ["<13>Oct  2 03:04:05 h a: m"] });
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);

            Assert.Equal(HttpStatusCode.BadRequest, (await manager.GetAsync("/api/logs?sort=rawLog")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().GetAsync("/api/logs")).StatusCode);
        }
        finally { await CleanupUserAsync(email); }
    }

    private async Task CleanupAsync(string source, DateTime started, string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.LogEvents.Where(e => e.Source == source).ExecuteDeleteAsync();
        await db.Alerts.Where(a => a.ReceivedAt >= started &&
            (a.SourceRuleId == "VPN-AUTH-FAILURE" || a.SourceRuleId == "LOG-IOC-MATCH" || a.SourceRuleId == "LOG-CRITICAL-SEVERITY"))
            .ExecuteDeleteAsync();
        await db.AuditLogs.Where(a => a.Action == "LOG_BATCH_INGESTED" && a.EntityId == source).ExecuteDeleteAsync();
        await CleanupUserAsync(email);
    }

    private async Task CleanupUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);
        if (user is null) return;
        db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
        db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id));
        db.AuditLogs.RemoveRange(db.AuditLogs.Where(a => a.ActorUserId == user.Id || a.ActorEmail == email));
        db.Users.Remove(user);
        await db.SaveChangesAsync();
    }
}
