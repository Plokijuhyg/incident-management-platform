using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Evidence;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class EvidenceControllerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public EvidenceControllerTests(TestApiFactory factory)
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
            db.Evidence.RemoveRange(db.Evidence.Where(e => incidentIds.Contains(e.IncidentId)));
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
            Title = "Evidence test incident", Description = "d", Severity = IncidentSeverity.Medium,
            Priority = IncidentPriority.Medium, Category = IncidentCategory.Other, Source = IncidentSource.Manual
        });
        var incident = await response.Content.ReadFromJsonAsync<IncidentDetailResponse>();
        return incident!.Id;
    }

    [Fact]
    public async Task Upload_AllowedFileType_ThenDownload_ReturnsSameContent()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            var fileContent = "suspicious log line\nanother line"u8.ToArray();
            using var content = new MultipartFormDataContent();
            using var fileStream = new ByteArrayContent(fileContent);
            fileStream.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            content.Add(fileStream, "file", "evidence.log");
            content.Add(new StringContent("LogFile"), "evidenceType");
            content.Add(new StringContent("Captured from suspicious process"), "description");

            var uploadResponse = await client.PostAsync($"/api/incidents/{incidentId}/evidence", content);
            Assert.Equal(HttpStatusCode.OK, uploadResponse.StatusCode);

            var uploaded = await uploadResponse.Content.ReadFromJsonAsync<EvidenceResponse>();
            Assert.Equal("evidence.log", uploaded!.OriginalFileName);
            Assert.Equal(64, uploaded.Sha256.Length); // SHA-256 hex length

            var downloadResponse = await client.GetAsync($"/api/incidents/{incidentId}/evidence/{uploaded.Id}/download");
            Assert.Equal(HttpStatusCode.OK, downloadResponse.StatusCode);

            var downloadedBytes = await downloadResponse.Content.ReadAsByteArrayAsync();
            Assert.Equal(fileContent, downloadedBytes);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Upload_DisallowedExtension_Returns400()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            using var content = new MultipartFormDataContent();
            using var fileStream = new ByteArrayContent("MZ fake exe header"u8.ToArray());
            fileStream.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(fileStream, "file", "malware.exe");
            content.Add(new StringContent("MalwareSample"), "evidenceType");

            var uploadResponse = await client.PostAsync($"/api/incidents/{incidentId}/evidence", content);

            Assert.Equal(HttpStatusCode.BadRequest, uploadResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Delete_AsAnalyst_Returns403()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            using var content = new MultipartFormDataContent();
            using var fileStream = new ByteArrayContent("data"u8.ToArray());
            fileStream.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            content.Add(fileStream, "file", "note.txt");
            content.Add(new StringContent("Document"), "evidenceType");

            var uploadResponse = await client.PostAsync($"/api/incidents/{incidentId}/evidence", content);
            var uploaded = await uploadResponse.Content.ReadFromJsonAsync<EvidenceResponse>();

            var deleteResponse = await client.DeleteAsync($"/api/incidents/{incidentId}/evidence/{uploaded!.Id}");
            Assert.Equal(HttpStatusCode.Forbidden, deleteResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetForIncident_ReturnsUploadedFilesList()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var incidentId = await CreateIncidentAsync(client);

            using var content = new MultipartFormDataContent();
            using var fileStream = new ByteArrayContent("screenshot data"u8.ToArray());
            fileStream.Headers.ContentType = new MediaTypeHeaderValue("image/png");
            content.Add(fileStream, "file", "screen.png");
            content.Add(new StringContent("Screenshot"), "evidenceType");

            await client.PostAsync($"/api/incidents/{incidentId}/evidence", content);

            var listResponse = await client.GetAsync($"/api/incidents/{incidentId}/evidence");
            var list = await listResponse.Content.ReadFromJsonAsync<List<EvidenceResponse>>();

            Assert.Single(list!);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
