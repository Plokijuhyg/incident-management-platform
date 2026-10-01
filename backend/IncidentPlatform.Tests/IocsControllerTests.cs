using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class IocsControllerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public IocsControllerTests(TestApiFactory factory)
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
            db.IncidentIocs.RemoveRange(db.IncidentIocs.Where(ii => incidentIds.Contains(ii.IncidentId)));
            db.Iocs.RemoveRange(db.Iocs.Where(i => i.CreatedById == user.Id));
            db.Alerts.RemoveRange(db.Alerts.Where(a => a.TriagedById == user.Id));
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
    public async Task Create_WithDefangedValue_NormalizesBeforeStoring()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/iocs", new IocCreateRequest
            {
                Type = IocType.Domain,
                Value = "EVIL[.]COM",
                Confidence = IocConfidence.High
            });

            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            var created = await createResponse.Content.ReadFromJsonAsync<IocResponse>();
            Assert.Equal("evil.com", created!.Value);
            Assert.Equal("EVIL[.]COM", created.RawValue);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Create_DuplicateNormalizedValue_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            await client.PostAsJsonAsync("/api/iocs", new IocCreateRequest
            {
                Type = IocType.Domain, Value = "evil.com", Confidence = IocConfidence.High
            });

            var secondResponse = await client.PostAsJsonAsync("/api/iocs", new IocCreateRequest
            {
                Type = IocType.Domain, Value = "EVIL.COM", Confidence = IocConfidence.Medium
            });

            Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Lookup_ForKnownIoc_ReturnsIt_AndForUnknown_Returns404()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            await client.PostAsJsonAsync("/api/iocs", new IocCreateRequest
            {
                Type = IocType.IpAddress, Value = "185.220.101.5", Confidence = IocConfidence.High
            });

            var foundResponse = await client.GetAsync("/api/iocs/lookup?type=IpAddress&value=185.220.101.5");
            Assert.Equal(HttpStatusCode.OK, foundResponse.StatusCode);

            var notFoundResponse = await client.GetAsync("/api/iocs/lookup?type=IpAddress&value=1.2.3.4");
            Assert.Equal(HttpStatusCode.NotFound, notFoundResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task LinkToIncident_TwiceWithSameIoc_SecondCallSightingCountIncrementsAndFindsExistingCatalogEntry()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var incident1 = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Incident A", Description = "d", Severity = IncidentSeverity.Medium,
                Priority = IncidentPriority.Medium, Category = IncidentCategory.Malware, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var incident2 = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Incident B", Description = "d", Severity = IncidentSeverity.Medium,
                Priority = IncidentPriority.Medium, Category = IncidentCategory.Malware, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkRequest = new LinkIocToIncidentRequest
            {
                Type = IocType.HashSha256,
                Value = "AABBCCDD00112233",
                Confidence = IocConfidence.Confirmed,
                Role = IocRole.Dropper
            };

            var firstLink = await (await client.PostAsJsonAsync($"/api/incidents/{incident1!.Id}/iocs", linkRequest))
                .Content.ReadFromJsonAsync<LinkIocResult>();
            Assert.True(firstLink!.WasNewlyCreated);
            Assert.Equal(1, firstLink.Ioc.SightingCount);

            var secondLink = await (await client.PostAsJsonAsync($"/api/incidents/{incident2!.Id}/iocs", linkRequest))
                .Content.ReadFromJsonAsync<LinkIocResult>();
            Assert.False(secondLink!.WasNewlyCreated);
            Assert.Equal(2, secondLink.Ioc.SightingCount);
            Assert.Equal(firstLink.Ioc.Id, secondLink.Ioc.Id);

            var detail = await (await client.GetAsync($"/api/iocs/{firstLink.Ioc.Id}"))
                .Content.ReadFromJsonAsync<IocDetailResponse>();
            Assert.Equal(2, detail!.Incidents.Count);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task LinkToIncident_SameIocSameIncidentTwice_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var incident = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Incident", Description = "d", Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low, Category = IncidentCategory.Other, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkRequest = new LinkIocToIncidentRequest
            {
                Type = IocType.Url, Value = "http://bad.example", Confidence = IocConfidence.Low, Role = IocRole.Other
            };

            await client.PostAsJsonAsync($"/api/incidents/{incident!.Id}/iocs", linkRequest);
            var secondAttempt = await client.PostAsJsonAsync($"/api/incidents/{incident.Id}/iocs", linkRequest);

            Assert.Equal(HttpStatusCode.Conflict, secondAttempt.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task UnlinkFromIncident_RemovesLinkButKeepsCatalogEntry()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var incident = await (await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
            {
                Title = "Incident", Description = "d", Severity = IncidentSeverity.Low,
                Priority = IncidentPriority.Low, Category = IncidentCategory.Other, Source = IncidentSource.Manual
            })).Content.ReadFromJsonAsync<IncidentDetailResponse>();

            var linkResult = await (await client.PostAsJsonAsync($"/api/incidents/{incident!.Id}/iocs", new LinkIocToIncidentRequest
            {
                Type = IocType.FileName, Value = "malware.exe", Confidence = IocConfidence.Medium, Role = IocRole.Payload
            })).Content.ReadFromJsonAsync<LinkIocResult>();

            var unlinkResponse = await client.DeleteAsync($"/api/incidents/{incident.Id}/iocs/{linkResult!.Ioc.Id}");
            Assert.Equal(HttpStatusCode.NoContent, unlinkResponse.StatusCode);

            // Catalog entry itself must still exist.
            var stillExistsResponse = await client.GetAsync($"/api/iocs/{linkResult.Ioc.Id}");
            Assert.Equal(HttpStatusCode.OK, stillExistsResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
