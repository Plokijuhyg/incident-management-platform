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

public class HexStrikeCatalogTests
{
    [Fact]
    public void Catalog_mirrors_the_reviewed_policy_and_marks_runnable_tools()
    {
        Assert.Equal(21, HexStrikeCatalog.ReviewedCount);
        Assert.Equal(4, HexStrikeCatalog.Categories.Length);

        var tools = HexStrikeCatalog.Tools();
        Assert.Equal(21, tools.Count(t => t.Runnable));
        Assert.All(tools, t => Assert.Contains(t.Category, HexStrikeCatalog.Categories));

        var nmap = tools.Single(t => t.Name == "nmap_scan");
        Assert.True(nmap.Runnable);
        Assert.Equal("safe", nmap.Tier);
        Assert.Equal("Network", nmap.Category);
        Assert.Equal("reviewed", nmap.Status);

        var sqlmap = tools.Single(t => t.Name == "sqlmap_scan");
        Assert.False(sqlmap.Runnable);
        Assert.Equal("advertised", sqlmap.Status);
        Assert.Contains("injection", sqlmap.Reason);

        Assert.All(tools.Where(t => t.Category == "Cloud"), t => Assert.False(t.Runnable));
    }
}

public class HexStrikeCatalogApiTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public HexStrikeCatalogApiTests(TestApiFactory factory) => _factory = factory;

    private async Task<(string Email, HttpClient Client)> ClientAsync(string role)
    {
        string email;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();
            email = $"cat-{Guid.NewGuid():N}@example.com";
            var user = new User { Email = email, FullName = "Catalog Tester", PasswordHash = hasher.Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            var r = await db.Roles.SingleAsync(x => x.Name == role);
            db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = r.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
            await db.SaveChangesAsync();
        }
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
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

    private sealed record CatalogResponse(bool enabled, string[] categories, int reviewedTotal, int advertisedTotal, int total, HexStrikeCatalog.ToolEntry[] tools);

    [Fact]
    public async Task Catalog_is_visible_offline_to_managers_and_denied_to_analysts()
    {
        var (managerEmail, manager) = await ClientAsync(RoleNames.SecurityManager);
        var (analystEmail, analyst) = await ClientAsync(RoleNames.SocAnalyst);
        try
        {
            var response = await manager.GetFromJsonAsync<CatalogResponse>("/api/assessments/catalog");
            Assert.False(response!.enabled);               // gateway disabled in Testing, catalog still available
            Assert.Equal(21, response.reviewedTotal);
            Assert.True(response.total >= 55);
            Assert.Equal(response.total, response.reviewedTotal + response.advertisedTotal);
            Assert.Contains(response.tools, t => t.Name == "nmap_scan" && t.Runnable);

            Assert.Equal(HttpStatusCode.Forbidden, (await analyst.GetAsync("/api/assessments/catalog")).StatusCode);
        }
        finally
        {
            await CleanupAsync(managerEmail);
            await CleanupAsync(analystEmail);
        }
    }
}
