using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class IncidentsControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public IncidentsControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private async Task<(string Email, int UserId)> CreateUserWithRoleAsync(string roleName)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();

        var email = $"test-{Guid.NewGuid():N}@example.com";
        var user = new User
        {
            Email = email,
            FullName = "Test User",
            PasswordHash = hasher.Hash("Password123!"),
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        var role = await db.Roles.SingleAsync(r => r.Name == roleName);
        db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id, AssignedAt = DateTime.UtcNow, AssignedById = user.Id });
        await db.SaveChangesAsync();

        return (email, user.Id);
    }

    private async Task CleanupUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var user = db.Users.SingleOrDefault(u => u.Email == email);
        if (user is not null)
        {
            db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
            db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id));
            db.Incidents.RemoveRange(db.Incidents.Where(i => i.CreatedById == user.Id || i.AssignedToId == user.Id));
            db.Users.Remove(user);
            await db.SaveChangesAsync();
        }
    }

    private async Task<HttpClient> AuthenticatedClientAsync(string email)
    {
        var client = _factory.CreateClient();
        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
        var body = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body!.AccessToken);
        return client;
    }

    [Fact]
    public async Task GetPaged_WithoutAuth_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Create_ThenGetById_ReturnsTheSameIncident()
    {
        var (email, _) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);

        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Suspicious login activity",
                Description = "Multiple failed logins from unusual IP",
                Severity = IncidentSeverity.High,
                Priority = IncidentPriority.High,
                Category = IncidentCategory.UnauthorizedAccess,
                Source = IncidentSource.Manual
            });

            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            Assert.NotNull(created);
            Assert.StartsWith($"INC-{DateTime.UtcNow.Year}-", created!.IncidentNumber);
            Assert.Equal(IncidentStatus.New, created.Status);

            var getResponse = await client.GetAsync($"/api/incidents/{created.Id}");
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

            var fetched = await getResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();
            Assert.Equal(created.IncidentNumber, fetched!.IncidentNumber);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetPaged_ReturnsEnvelopeWithCorrectShape()
    {
        var (email, _) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);

        try
        {
            var client = await AuthenticatedClientAsync(email);

            await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Test incident for paging",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });

            var response = await client.GetAsync("/api/incidents?page=1&pageSize=10");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var page = await response.Content.ReadFromJsonAsync<PagedResult<IncidentSummaryResponse>>();
            Assert.NotNull(page);
            Assert.True(page!.TotalCount >= 1);
            Assert.Equal(1, page.Page);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Assign_AsAnalyst_Returns403()
    {
        var (analystEmail, _) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);
        var (managerEmail, managerId) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);

        try
        {
            var analystClient = await AuthenticatedClientAsync(analystEmail);

            var createResponse = await analystClient.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Needs assignment",
                Description = "desc",
                Severity = IncidentSeverity.Medium,
                Priority = IncidentPriority.Medium,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var assignResponse = await analystClient.PostAsJsonAsync(
                $"/api/incidents/{created!.Id}/assign", new AssignIncidentRequest { AssignedToId = managerId });

            Assert.Equal(HttpStatusCode.Forbidden, assignResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(analystEmail);
            await CleanupUserAsync(managerEmail);
        }
    }

    [Fact]
    public async Task Assign_AsManager_Succeeds_AndUnassignedAnalystCannotThenUpdateIt()
    {
        var (analystEmail, analystId) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);
        var (otherAnalystEmail, _) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);
        var (managerEmail, _) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);

        try
        {
            var managerClient = await AuthenticatedClientAsync(managerEmail);

            var createResponse = await managerClient.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Assign me",
                Description = "desc",
                Severity = IncidentSeverity.Medium,
                Priority = IncidentPriority.Medium,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var assignResponse = await managerClient.PostAsJsonAsync(
                $"/api/incidents/{created!.Id}/assign", new AssignIncidentRequest { AssignedToId = analystId });
            Assert.Equal(HttpStatusCode.OK, assignResponse.StatusCode);

            // The OTHER analyst (not assigned) must not be able to update it.
            var otherAnalystClient = await AuthenticatedClientAsync(otherAnalystEmail);
            var updateResponse = await otherAnalystClient.PutAsJsonAsync($"/api/incidents/{created.Id}", new IncidentUpdateRequest
            {
                Title = "Hijacked update",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Version = 1
            });

            Assert.Equal(HttpStatusCode.Forbidden, updateResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(analystEmail);
            await CleanupUserAsync(otherAnalystEmail);
            await CleanupUserAsync(managerEmail);
        }
    }

    [Fact]
    public async Task Update_WithStaleVersion_Returns409()
    {
        var (email, _) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);

        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Version test",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var staleUpdateResponse = await client.PutAsJsonAsync($"/api/incidents/{created!.Id}", new IncidentUpdateRequest
            {
                Title = "Updated title",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Version = 999 // deliberately wrong
            });

            Assert.Equal(HttpStatusCode.Conflict, staleUpdateResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task ChangeStatus_ToTriaged_SetsTriagedAtTimestamp()
    {
        var (email, _) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);

        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Status test",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var statusResponse = await client.PostAsJsonAsync($"/api/incidents/{created!.Id}/status",
                new ChangeStatusRequest { Status = IncidentStatus.Triaged, Note = "Reviewed" });

            Assert.Equal(HttpStatusCode.OK, statusResponse.StatusCode);
            var updated = await statusResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();
            Assert.NotNull(updated!.TriagedAt);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Close_AsAnalyst_Returns403()
    {
        var (email, _) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);

        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Close test",
                Description = "desc",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Manual
            });
            var created = await createResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var closeResponse = await client.PostAsJsonAsync($"/api/incidents/{created!.Id}/close",
                new CloseIncidentRequest { ResolutionSummary = "Fixed" });

            Assert.Equal(HttpStatusCode.Forbidden, closeResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
