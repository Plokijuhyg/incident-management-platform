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

public class IncidentsControllerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public IncidentsControllerTests(TestApiFactory factory)
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
            db.AuditLogs.RemoveRange(db.AuditLogs.Where(a => a.ActorUserId == user.Id || a.ActorEmail == email));
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

    private static IncidentCreateRequest NewIncident(string title) => new()
    {
        Title = title,
        Description = "desc",
        Severity = IncidentSeverity.Low,
        Priority = IncidentPriority.Low,
        Category = IncidentCategory.Other,
        Source = IncidentSource.Manual
    };

    [Fact]
    public async Task ChangeStatus_ToClosed_Returns400_EvenForAssignedAnalyst()
    {
        var (managerEmail, _) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);
        var (analystEmail, analystId) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);

        try
        {
            var manager = await AuthenticatedClientAsync(managerEmail);
            var created = await (await manager.PostAsJsonAsync("/api/incidents", NewIncident("Close bypass test")))
                .Content.ReadFromJsonAsync<IncidentDetailResponse>();
            (await manager.PostAsJsonAsync($"/api/incidents/{created!.Id}/assign",
                new AssignIncidentRequest { AssignedToId = analystId })).EnsureSuccessStatusCode();

            var analyst = await AuthenticatedClientAsync(analystEmail);
            var response = await analyst.PostAsJsonAsync($"/api/incidents/{created.Id}/status",
                new ChangeStatusRequest { Status = IncidentStatus.Closed });

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var current = await analyst.GetFromJsonAsync<IncidentDetailResponse>($"/api/incidents/{created.Id}");
            Assert.NotEqual(IncidentStatus.Closed, current!.Status);
            Assert.Null(current.ClosedAt);
        }
        finally
        {
            await CleanupUserAsync(analystEmail);
            await CleanupUserAsync(managerEmail);
        }
    }

    [Fact]
    public async Task ChangeStatus_ReopenClosedIncident_RequiresManagerAndClearsClosedAt()
    {
        var (managerEmail, _) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);
        var (analystEmail, analystId) = await CreateUserWithRoleAsync(RoleNames.SocAnalyst);

        try
        {
            var manager = await AuthenticatedClientAsync(managerEmail);
            var created = await (await manager.PostAsJsonAsync("/api/incidents", NewIncident("Reopen test")))
                .Content.ReadFromJsonAsync<IncidentDetailResponse>();
            (await manager.PostAsJsonAsync($"/api/incidents/{created!.Id}/assign",
                new AssignIncidentRequest { AssignedToId = analystId })).EnsureSuccessStatusCode();
            (await manager.PostAsJsonAsync($"/api/incidents/{created.Id}/close",
                new CloseIncidentRequest { ResolutionSummary = "Done" })).EnsureSuccessStatusCode();

            var analyst = await AuthenticatedClientAsync(analystEmail);
            var analystReopen = await analyst.PostAsJsonAsync($"/api/incidents/{created.Id}/status",
                new ChangeStatusRequest { Status = IncidentStatus.Investigating });
            Assert.Equal(HttpStatusCode.Forbidden, analystReopen.StatusCode);

            var managerReopen = await manager.PostAsJsonAsync($"/api/incidents/{created.Id}/status",
                new ChangeStatusRequest { Status = IncidentStatus.Investigating, Note = "New evidence" });
            Assert.Equal(HttpStatusCode.OK, managerReopen.StatusCode);
            var reopened = await managerReopen.Content.ReadFromJsonAsync<IncidentDetailResponse>();
            Assert.Equal(IncidentStatus.Investigating, reopened!.Status);
            Assert.Null(reopened.ClosedAt);
        }
        finally
        {
            await CleanupUserAsync(analystEmail);
            await CleanupUserAsync(managerEmail);
        }
    }

    [Fact]
    public async Task GetPaged_FiltersSearchesAndSortsTheRegister()
    {
        var (managerEmail, managerId) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);
        // The test database is shared with other tests; a unique token scopes every query.
        var token = $"q{Guid.NewGuid():N}"[..12];

        try
        {
            var client = await AuthenticatedClientAsync(managerEmail);
            async Task<IncidentDetailResponse> Create(string title, IncidentSeverity severity)
            {
                var request = NewIncident($"{title} {token}");
                request.Severity = severity;
                var response = await client.PostAsJsonAsync("/api/incidents", request);
                response.EnsureSuccessStatusCode();
                return (await response.Content.ReadFromJsonAsync<IncidentDetailResponse>())!;
            }
            var low = await Create("Adware", IncidentSeverity.Low);
            var critical = await Create("Domain admin compromise", IncidentSeverity.Critical);
            var medium = await Create("Phishing click", IncidentSeverity.Medium);
            (await client.PostAsJsonAsync($"/api/incidents/{critical.Id}/assign",
                new AssignIncidentRequest { AssignedToId = managerId })).EnsureSuccessStatusCode();
            (await client.PostAsJsonAsync($"/api/incidents/{low.Id}/close",
                new CloseIncidentRequest { ResolutionSummary = "Removed" })).EnsureSuccessStatusCode();

            async Task<List<int>> Ids(string query) =>
                (await client.GetFromJsonAsync<PagedResult<IncidentSummaryResponse>>($"/api/incidents?search={token}&{query}"))!
                    .Items.Select(i => i.Id).ToList();

            Assert.Equal([medium.Id, critical.Id, low.Id], await Ids(""));                     // newest first by default
            Assert.Equal([critical.Id, medium.Id, low.Id], await Ids("sort=severity"));        // not alphabetical
            Assert.Equal([low.Id, medium.Id, critical.Id], await Ids("sort=severity&direction=asc"));
            Assert.Equal([critical.Id], await Ids("severity=Critical"));
            Assert.Equal([critical.Id], await Ids($"assignedToId={managerId}"));
            Assert.Equal([medium.Id, low.Id], await Ids("unassigned=true"));
            Assert.Equal([medium.Id, critical.Id], await Ids("openOnly=true"));
            Assert.Equal([low.Id], await Ids("status=Closed"));
            Assert.Equal([critical.Id], (await client.GetFromJsonAsync<PagedResult<IncidentSummaryResponse>>(
                $"/api/incidents?search={Uri.EscapeDataString(critical.IncidentNumber)}"))!.Items.Select(i => i.Id).ToList());

            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/incidents?sort=description")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync($"/api/incidents?assignedToId={managerId}&unassigned=true")).StatusCode);
        }
        finally
        {
            await CleanupUserAsync(managerEmail);
        }
    }

    private sealed class FixedUser(int id, params string[] roles) : IncidentPlatform.Api.Interfaces.ICurrentUser
    {
        public int Id => id;
        public IReadOnlyList<string> Roles => roles;
        public bool IsInRole(string role) => roles.Contains(role);
    }

    [Fact]
    public async Task StatusAssignAndClose_OnConcurrentlyModifiedIncident_ThrowConflict()
    {
        var (managerEmail, managerId) = await CreateUserWithRoleAsync(RoleNames.SecurityManager);

        try
        {
            var manager = await AuthenticatedClientAsync(managerEmail);
            var created = await (await manager.PostAsJsonAsync("/api/incidents", NewIncident("Concurrency test")))
                .Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var operations = new Func<IncidentPlatform.Api.Services.IncidentService, Task>[]
            {
                s => s.ChangeStatusAsync(created!.Id, new ChangeStatusRequest { Status = IncidentStatus.Triaged }),
                s => s.AssignAsync(created!.Id, new AssignIncidentRequest { AssignedToId = managerId }),
                s => s.CloseAsync(created!.Id, new CloseIncidentRequest { ResolutionSummary = "Done" })
            };

            foreach (var operation in operations)
            {
                // Context A tracks the incident; another writer then bumps Version underneath it.
                using var scope = _factory.Services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                Assert.NotNull(await db.Incidents.FindAsync(created!.Id));
                using (var otherScope = _factory.Services.CreateScope())
                {
                    var other = otherScope.ServiceProvider.GetRequiredService<AppDbContext>();
                    await other.Incidents.Where(i => i.Id == created.Id)
                        .ExecuteUpdateAsync(u => u.SetProperty(i => i.Version, i => i.Version + 1));
                }

                var service = new IncidentPlatform.Api.Services.IncidentService(db, new FixedUser(managerId, RoleNames.SecurityManager));
                await Assert.ThrowsAsync<IncidentPlatform.Api.Exceptions.ConflictException>(() => operation(service));
            }
        }
        finally
        {
            await CleanupUserAsync(managerEmail);
        }
    }
}
