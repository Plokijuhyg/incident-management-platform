using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Alerts;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class AlertsControllerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public AlertsControllerTests(TestApiFactory factory)
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
        // Alerts.TriagedById -> Users is RESTRICT, so any alert this user
        // triaged (promoted or marked false-positive) must go first.
        db.Alerts.RemoveRange(db.Alerts.Where(a => a.TriagedById == user.Id || db.AuditLogs.Any(log => log.ActorUserId == user.Id && log.EntityType == "Alert" && log.EntityId == a.Id.ToString() && log.Action == "ALERT_CREATED")));

        // Incidents.CreatedById / AssignedToId -> Users are also RESTRICT.
        // IncidentTimelineEvents CASCADE from Incident, so deleting the
        // incident cleans those up automatically; Alerts.IncidentId is
        // SET NULL, so any remaining alert pointing at these incidents is
        // safely unlinked rather than blocking the delete.
        db.Incidents.RemoveRange(db.Incidents.Where(i => i.CreatedById == user.Id || i.AssignedToId == user.Id));

        db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
        db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id));
        db.AuditLogs.RemoveRange(db.AuditLogs.Where(a => a.ActorUserId == user.Id || a.ActorEmail == email));
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
    public async Task Create_ThenGetById_ReturnsTheSameAlert()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/alerts", new AlertCreateRequest
            {
                Title = "Suspicious PowerShell execution",
                Source = AlertSource.Edr,
                Severity = "HIGH",
                DetectedAt = DateTime.UtcNow.AddMinutes(-10),
                RawPayload = "{\"process\":\"powershell.exe\"}"
            });

            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            var created = await createResponse.Content.ReadFromJsonAsync<AlertDetailResponse>();
            Assert.Equal(AlertStatus.New, created!.Status);

            var getResponse = await client.GetAsync($"/api/alerts/{created.Id}");
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Promote_CreatesLinkedIncident_AndSetsAlertStatusToPromoted()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/alerts", new AlertCreateRequest
            {
                Title = "Malware detected",
                Source = AlertSource.Edr,
                Severity = "CRITICAL",
                DetectedAt = DateTime.UtcNow.AddMinutes(-30)
            });
            var alert = await createResponse.Content.ReadFromJsonAsync<AlertDetailResponse>();

            var promoteResponse = await client.PostAsJsonAsync($"/api/alerts/{alert!.Id}/promote", new PromoteAlertRequest
            {
                Title = "Malware infection on workstation",
                Severity = IncidentSeverity.Critical,
                Priority = IncidentPriority.Urgent,
                Category = IncidentCategory.Malware
            });

            Assert.Equal(HttpStatusCode.OK, promoteResponse.StatusCode);
            var incident = await promoteResponse.Content.ReadFromJsonAsync<IncidentDetailResponse>();
            Assert.StartsWith("INC-", incident!.IncidentNumber);

            var alertAfter = await (await client.GetAsync($"/api/alerts/{alert.Id}")).Content.ReadFromJsonAsync<AlertDetailResponse>();
            Assert.Equal(AlertStatus.Promoted, alertAfter!.Status);
            Assert.Equal(incident.Id, alertAfter.IncidentId);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Promote_AnAlreadyPromotedAlert_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/alerts", new AlertCreateRequest
            {
                Title = "Double promote test",
                Source = AlertSource.Manual,
                Severity = "LOW",
                DetectedAt = DateTime.UtcNow
            });
            var alert = await createResponse.Content.ReadFromJsonAsync<AlertDetailResponse>();

            var promoteRequest = new PromoteAlertRequest
            {
                Title = "First promotion",
                Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low,
                Category = IncidentCategory.Other
            };

            await client.PostAsJsonAsync($"/api/alerts/{alert!.Id}/promote", promoteRequest);
            var secondAttempt = await client.PostAsJsonAsync($"/api/alerts/{alert.Id}/promote", promoteRequest);

            Assert.Equal(HttpStatusCode.Conflict, secondAttempt.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task MarkFalsePositive_SetsStatusAndAppendsReason()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/alerts", new AlertCreateRequest
            {
                Title = "Benign scan",
                Source = AlertSource.Ids,
                Severity = "LOW",
                DetectedAt = DateTime.UtcNow
            });
            var alert = await createResponse.Content.ReadFromJsonAsync<AlertDetailResponse>();

            var fpResponse = await client.PostAsJsonAsync($"/api/alerts/{alert!.Id}/false-positive",
                new FalsePositiveRequest { Reason = "Known internal vulnerability scanner" });

            Assert.Equal(HttpStatusCode.OK, fpResponse.StatusCode);
            var updated = await fpResponse.Content.ReadFromJsonAsync<AlertDetailResponse>();
            Assert.Equal(AlertStatus.FalsePositive, updated!.Status);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetPaged_FilteredByStatus_OnlyReturnsMatchingAlerts()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            await client.PostAsJsonAsync("/api/alerts", new AlertCreateRequest
            {
                Title = "Filter test", Source = AlertSource.Manual, Severity = "LOW", DetectedAt = DateTime.UtcNow
            });

            var response = await client.GetAsync("/api/alerts?status=New&pageSize=50");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}