using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class AssetsControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AssetsControllerTests(WebApplicationFactory<Program> factory)
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
            db.IncidentAssets.RemoveRange(db.IncidentAssets.Where(ia => incidentIds.Contains(ia.IncidentId)));
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
    public async Task Create_AsAnalyst_Returns403()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var response = await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "WEB-SRV-01", Type = AssetType.Server, Criticality = AssetCriticality.High
            });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Create_AsManager_ThenGetById_ReturnsIt()
    {
        var email = await CreateUserAsync(RoleNames.SecurityManager);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "DB-SRV-01", Hostname = "db-srv-01.corp.local", Type = AssetType.Server, Criticality = AssetCriticality.Critical
            });

            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            var created = await createResponse.Content.ReadFromJsonAsync<AssetResponse>();

            var getResponse = await client.GetAsync($"/api/assets/{created!.Id}");
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Create_DuplicateHostname_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.SecurityManager);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "Host A", Hostname = "dup.corp.local", Type = AssetType.Workstation, Criticality = AssetCriticality.Low
            });

            var secondResponse = await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "Host B", Hostname = "dup.corp.local", Type = AssetType.Workstation, Criticality = AssetCriticality.Low
            });

            Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task LinkAssetToIncident_ThenUnlink_Succeeds_AndAssetSurvives()
    {
        var email = await CreateUserAsync(RoleNames.SecurityManager);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var asset = await (await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "PATIENT-ZERO-01", Type = AssetType.Workstation, Criticality = AssetCriticality.Medium
            })).Content.ReadFromJsonAsync<AssetResponse>();

            var incident = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Malware spread", Description = "d", Severity = IncidentSeverity.High,
                Priority = IncidentPriority.High, Category = IncidentCategory.Malware, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkResponse = await client.PostAsJsonAsync($"/api/incidents/{incident!.Id}/assets", new LinkAssetToIncidentRequest
            {
                AssetId = asset!.Id, ImpactType = ImpactType.PatientZero
            });
            Assert.Equal(HttpStatusCode.NoContent, linkResponse.StatusCode);

            var detail = await (await client.GetAsync($"/api/assets/{asset.Id}")).Content.ReadFromJsonAsync<AssetDetailResponse>();
            Assert.Single(detail!.Incidents);
            Assert.Equal(ImpactType.PatientZero, detail.Incidents[0].ImpactType);

            var unlinkResponse = await client.DeleteAsync($"/api/incidents/{incident.Id}/assets/{asset.Id}");
            Assert.Equal(HttpStatusCode.NoContent, unlinkResponse.StatusCode);

            var stillExists = await client.GetAsync($"/api/assets/{asset.Id}");
            Assert.Equal(HttpStatusCode.OK, stillExists.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task LinkAssetToIncident_Twice_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.SecurityManager);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var asset = await (await client.PostAsJsonAsync("/api/assets", new AssetCreateRequest
            {
                Name = "DOUBLE-LINK-01", Type = AssetType.Workstation, Criticality = AssetCriticality.Low
            })).Content.ReadFromJsonAsync<AssetResponse>();

            var incident = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Double link test", Description = "d", Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low, Category = IncidentCategory.Other, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkRequest = new LinkAssetToIncidentRequest { AssetId = asset!.Id, ImpactType = ImpactType.Affected };

            await client.PostAsJsonAsync($"/api/incidents/{incident!.Id}/assets", linkRequest);
            var secondAttempt = await client.PostAsJsonAsync($"/api/incidents/{incident.Id}/assets", linkRequest);

            Assert.Equal(HttpStatusCode.Conflict, secondAttempt.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
