using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.Mitre;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class MitreControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public MitreControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private async Task<string> CreateUserAsync(string roleName)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();

        var email = $"test-{Guid.NewGuid():N}@example.com";
        var user = new User
        {
            Email = email, FullName = "Test User", PasswordHash = hasher.Hash("Password123!"),
            IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var role = await db.Roles.SingleAsync(r => r.Name == roleName);
        db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
        await db.SaveChangesAsync();

        return email;
    }

    private async Task CleanupUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var user = db.Users.SingleOrDefault(u => u.Email == email);
        if (user is not null)
        {
            var incidentIds = db.Incidents.Where(i => i.CreatedById == user.Id).Select(i => i.Id).ToList();
            db.IncidentMitreTechniques.RemoveRange(db.IncidentMitreTechniques.Where(imt => incidentIds.Contains(imt.IncidentId)));
            db.Incidents.RemoveRange(db.Incidents.Where(i => i.CreatedById == user.Id || i.AssignedToId == user.Id));
            db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
            db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id));
            db.Users.Remove(user);
            await db.SaveChangesAsync();
        }
    }

    private async Task<HttpClient> AuthenticatedClientAsync(string email)
    {
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
        var body = await login.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.AccessToken);
        return client;
    }

    [Fact]
    public async Task GetTechniques_ReturnsSeededData()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var response = await client.GetAsync("/api/mitre/techniques");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var techniques = await response.Content.ReadFromJsonAsync<List<MitreTechniqueResponse>>();
            Assert.NotEmpty(techniques!);
            Assert.Contains(techniques!, t => t.TechniqueId == "T1566");
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetByTechniqueId_KnownId_ReturnsIt_AndUnknown_Returns404()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var found = await client.GetAsync("/api/mitre/techniques/T1059");
            Assert.Equal(HttpStatusCode.OK, found.StatusCode);

            var notFound = await client.GetAsync("/api/mitre/techniques/T9999");
            Assert.Equal(HttpStatusCode.NotFound, notFound.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task SubTechnique_HasCorrectParentLink()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var parent = await (await client.GetAsync("/api/mitre/techniques/T1566"))
                .Content.ReadFromJsonAsync<MitreTechniqueResponse>();
            var child = await (await client.GetAsync("/api/mitre/techniques/T1566.001"))
                .Content.ReadFromJsonAsync<MitreTechniqueResponse>();

            Assert.True(child!.IsSubTechnique);
            Assert.Equal(parent!.Id, child.ParentTechniqueId);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetTactics_ReturnsDistinctSortedList()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var response = await client.GetAsync("/api/mitre/tactics");
            var tactics = await response.Content.ReadFromJsonAsync<List<string>>();

            Assert.Contains("Initial Access", tactics!);
            Assert.Equal(tactics!.Distinct().Count(), tactics!.Count);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task LinkTechniqueToIncident_ThenUnlink_Succeeds()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var technique = await (await client.GetAsync("/api/mitre/techniques/T1190"))
                .Content.ReadFromJsonAsync<MitreTechniqueResponse>();

            var incident = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Exploited web app", Description = "d", Severity = IncidentSeverity.High,
                Priority = IncidentPriority.High, Category = IncidentCategory.Vulnerability, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkResponse = await client.PostAsJsonAsync($"/api/incidents/{incident!.Id}/mitre-techniques",
                new LinkMitreTechniqueRequest { MitreTechniqueId = technique!.Id, Notes = "Confirmed via logs" });
            Assert.Equal(HttpStatusCode.NoContent, linkResponse.StatusCode);

            var unlinkResponse = await client.DeleteAsync($"/api/incidents/{incident.Id}/mitre-techniques/{technique.Id}");
            Assert.Equal(HttpStatusCode.NoContent, unlinkResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
