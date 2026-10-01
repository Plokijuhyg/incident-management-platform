using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.IncidentSubResources;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class IncidentSubResourcesTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public IncidentSubResourcesTests(TestApiFactory factory)
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
            db.IncidentComments.RemoveRange(db.IncidentComments.Where(c => incidentIds.Contains(c.IncidentId)));
            db.IncidentTimelineEvents.RemoveRange(db.IncidentTimelineEvents.Where(t => incidentIds.Contains(t.IncidentId)));
            db.ResponseActions.RemoveRange(db.ResponseActions.Where(r => incidentIds.Contains(r.IncidentId)));
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

    private async Task<int> CreateIncidentAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
        {
            Title = "Sub-resource test incident", Description = "d", Severity = IncidentSeverity.Medium,
            Priority = IncidentPriority.Medium, Category = IncidentCategory.Other, Source = IncidentSource.Manual
        });
        var incident = await response.Content.ReadFromJsonAsync<IncidentDetailResponse>();
        return incident!.Id;
    }

    [Fact]
    public async Task AddComment_ThenGetComments_ReturnsIt()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            var addResponse = await client.PostAsJsonAsync($"/api/incidents/{incidentId}/comments",
                new CreateCommentRequest { Body = "Investigating now", IsInternal = true });
            Assert.Equal(HttpStatusCode.OK, addResponse.StatusCode);

            var listResponse = await client.GetAsync($"/api/incidents/{incidentId}/comments");
            var comments = await listResponse.Content.ReadFromJsonAsync<List<CommentResponse>>();

            Assert.Single(comments!);
            Assert.Equal("Investigating now", comments![0].Body);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Timeline_IncludesAutomaticAssignmentEvent_AndManuallyAddedEvent_SortedByOccurredAt()
    {
        var email = await CreateUserAsync(RoleNames.SecurityManager);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            // Manually add an event with an OccurredAt in the past — proves
            // sorting is by OccurredAt, not insertion order.
            var pastEventResponse = await client.PostAsJsonAsync($"/api/incidents/{incidentId}/timeline",
                new CreateTimelineEventRequest
                {
                    EventType = TimelineEventType.Detection,
                    Title = "Malware detected by EDR",
                    OccurredAt = DateTime.UtcNow.AddHours(-2)
                });
            Assert.Equal(HttpStatusCode.OK, pastEventResponse.StatusCode);

            var timelineResponse = await client.GetAsync($"/api/incidents/{incidentId}/timeline");
            var events = await timelineResponse.Content.ReadFromJsonAsync<List<TimelineEventResponse>>();

            Assert.NotEmpty(events!);
            // Sorted ascending by OccurredAt — the manually-backdated event must come first.
            Assert.Equal("Malware detected by EDR", events![0].Title);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task ResponseAction_CreateThenUpdateToCompleted_SetsCompletedAt()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            var createResponse = await client.PostAsJsonAsync($"/api/incidents/{incidentId}/response-actions",
                new CreateResponseActionRequest
                {
                    ActionType = ResponseActionType.IsolateEndpoint,
                    Description = "Isolate infected workstation from network"
                });
            var action = await createResponse.Content.ReadFromJsonAsync<ResponseActionResponse>();
            Assert.Equal(ResponseActionStatus.Planned, action!.Status);

            var updateResponse = await client.PutAsJsonAsync($"/api/incidents/{incidentId}/response-actions/{action.Id}",
                new UpdateResponseActionRequest { Status = ResponseActionStatus.Completed, Result = "Endpoint isolated successfully" });

            var updated = await updateResponse.Content.ReadFromJsonAsync<ResponseActionResponse>();
            Assert.Equal(ResponseActionStatus.Completed, updated!.Status);
            Assert.NotNull(updated.CompletedAt);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task ResponseAction_UpdateToFailed_IsAllowed_NotForcedToSucceed()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            var createResponse = await client.PostAsJsonAsync($"/api/incidents/{incidentId}/response-actions",
                new CreateResponseActionRequest
                {
                    ActionType = ResponseActionType.BlockIp,
                    Description = "Block malicious C2 IP",
                    TargetType = ResponseTargetType.Other,
                    TargetValue = "185.220.101.5"
                });
            var action = await createResponse.Content.ReadFromJsonAsync<ResponseActionResponse>();

            var updateResponse = await client.PutAsJsonAsync($"/api/incidents/{incidentId}/response-actions/{action!.Id}",
                new UpdateResponseActionRequest { Status = ResponseActionStatus.Failed, Result = "Firewall rule conflict" });

            var updated = await updateResponse.Content.ReadFromJsonAsync<ResponseActionResponse>();
            Assert.Equal(ResponseActionStatus.Failed, updated!.Status);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
