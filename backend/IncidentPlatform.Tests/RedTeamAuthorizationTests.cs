using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

// The RED_TEAM lab identity may use the Assessments module but is denied every
// blue-team/SOC endpoint. These assert the actual HTTP outcomes (200 vs 403),
// not just allow-list membership.
public class RedTeamAuthorizationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public RedTeamAuthorizationTests(TestApiFactory factory) => _factory = factory;

    private async Task<(string Email, HttpClient Client)> ClientAsync(string role)
    {
        string email;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
            email = $"rt-{Guid.NewGuid():N}@example.com";
            var user = new User { Email = email, FullName = "RT Tester", PasswordHash = hasher.Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            var r = await db.Roles.SingleAsync(x => x.Name == role);
            db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = r.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
            await db.SaveChangesAsync();
        }
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
        login.EnsureSuccessStatusCode();
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.AccessToken);
        return (email, client);
    }

    private async Task CleanupAsync(string email)
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

    [Fact]
    public async Task RedTeam_role_is_seeded()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.True(await db.Roles.AnyAsync(r => r.Name == RoleNames.RedTeam));
    }

    [Fact]
    public async Task RedTeam_can_use_assessments_but_is_denied_the_soc_pipeline()
    {
        var (email, client) = await ClientAsync(RoleNames.RedTeam);
        try
        {
            // Allowed: the Assessments module (target/tool selection + results).
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/assessments/catalog")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/assessments")).StatusCode);

            // Denied (403, not just absent): the blue-team / SOC endpoints.
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/incidents")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/alerts")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/dashboard/summary")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/soc/overview")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/users")).StatusCode);
        }
        finally
        {
            await CleanupAsync(email);
        }
    }

    [Fact]
    public async Task SocAnalyst_keeps_access_to_the_blue_team_pipeline()
    {
        // Guards against the controller tightening accidentally locking out blue roles.
        var (email, client) = await ClientAsync(RoleNames.SocAnalyst);
        try
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/incidents")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/alerts")).StatusCode);
        }
        finally
        {
            await CleanupAsync(email);
        }
    }
}
