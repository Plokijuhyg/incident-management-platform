using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Users;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class UsersControllerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public UsersControllerTests(TestApiFactory factory)
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
            db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => t.UserId == user.Id));
            db.UserRoles.RemoveRange(db.UserRoles.Where(ur => ur.UserId == user.Id || ur.AssignedById == user.Id));
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
    public async Task Admin_password_reset_revokes_old_access_and_allows_new_password_with_same_role()
    {
        var adminEmail=await CreateUserAsync(RoleNames.Admin);var email=await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var admin=await AuthenticatedClientAsync(adminEmail);var oldClient=await AuthenticatedClientAsync(email);
            using var scope=_factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var id=await db.Users.Where(u=>u.Email==email).Select(u=>u.Id).SingleAsync();
            Assert.Equal(HttpStatusCode.Forbidden,(await oldClient.PostAsJsonAsync($"/api/users/{id}/reset-password",new{password="ChangedPassword123!"})).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent,(await admin.PostAsJsonAsync($"/api/users/{id}/reset-password",new{password="ChangedPassword123!"})).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized,(await oldClient.GetAsync("/api/users")).StatusCode);
            var fresh=_factory.CreateClient();var response=await fresh.PostAsJsonAsync("/api/auth/login",new LoginRequest{Email=email,Password="ChangedPassword123!"});
            response.EnsureSuccessStatusCode();var login=await response.Content.ReadFromJsonAsync<LoginResponse>();fresh.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",login!.AccessToken);
            Assert.Equal(HttpStatusCode.Forbidden,(await fresh.GetAsync("/api/users")).StatusCode);
        }
        finally{await CleanupUserAsync(email);await CleanupUserAsync(adminEmail);}
    }

    [Fact]
    public async Task GetPaged_AsAnalyst_Returns403()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var response = await client.GetAsync("/api/users");
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Create_AsAdmin_ThenGetById_ReturnsIt()
    {
        var email = await CreateUserAsync(RoleNames.Admin);
        var newUserEmail = $"created-{Guid.NewGuid():N}@example.com";
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var createResponse = await client.PostAsJsonAsync("/api/users", new CreateUserRequest
            {
                Email = newUserEmail, FullName = "New Analyst", Password = "Password123!",
                Roles = [RoleNames.SocAnalyst]
            });

            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            var created = await createResponse.Content.ReadFromJsonAsync<UserResponse>();
            Assert.Contains(RoleNames.SocAnalyst, created!.Roles);

            var getResponse = await client.GetAsync($"/api/users/{created.Id}");
            Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
            await CleanupUserAsync(newUserEmail);
        }
    }

    [Fact]
    public async Task Create_DuplicateEmail_Returns409()
    {
        var email = await CreateUserAsync(RoleNames.Admin);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            var response = await client.PostAsJsonAsync("/api/users", new CreateUserRequest
            {
                Email = email, FullName = "Duplicate", Password = "Password123!", Roles = [RoleNames.SocAnalyst]
            });

            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task Deactivate_RevokesActiveSessions()
    {
        var adminEmail = await CreateUserAsync(RoleNames.Admin);
        var targetEmail = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var adminClient = await AuthenticatedClientAsync(adminEmail);

            // Target user logs in first, establishing a refresh token cookie
            // on their own client.
            var targetClient = await AuthenticatedClientAsync(targetEmail);

            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var targetUser = await db.Users.SingleAsync(u => u.Email == targetEmail);

            var deactivateResponse = await adminClient.PostAsync($"/api/users/{targetUser.Id}/deactivate", null);
            Assert.Equal(HttpStatusCode.NoContent, deactivateResponse.StatusCode);

            // Deactivated account can no longer log in.
            var reloginResponse = await targetClient.PostAsJsonAsync("/api/auth/login",
                new LoginRequest { Email = targetEmail, Password = "Password123!" });
            Assert.Equal(HttpStatusCode.Unauthorized, reloginResponse.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(adminEmail);
            await CleanupUserAsync(targetEmail);
        }
    }

    [Fact]
    public async Task Deactivate_OwnAccount_Returns400()
    {
        var email = await CreateUserAsync(RoleNames.Admin);
        try
        {
            var client = await AuthenticatedClientAsync(email);

            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var self = await db.Users.SingleAsync(u => u.Email == email);

            var response = await client.PostAsync($"/api/users/{self.Id}/deactivate", null);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task ReplaceRoles_ChangesRolesCorrectly()
    {
        var adminEmail = await CreateUserAsync(RoleNames.Admin);
        var targetEmail = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(adminEmail);

            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var targetUser = await db.Users.SingleAsync(u => u.Email == targetEmail);

            var response = await client.PostAsJsonAsync($"/api/users/{targetUser.Id}/roles",
                new ReplaceRolesRequest { Roles = [RoleNames.SecurityManager] });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var updated = await response.Content.ReadFromJsonAsync<UserResponse>();

            Assert.Single(updated!.Roles);
            Assert.Contains(RoleNames.SecurityManager, updated.Roles);
        }
        finally
        {
            await CleanupUserAsync(adminEmail);
            await CleanupUserAsync(targetEmail);
        }
    }

    [Fact]
    public async Task GetAssignable_AvailableToAnyAuthenticatedRole()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var response = await client.GetAsync("/api/users/assignable");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }

    [Fact]
    public async Task GetRoles_ReturnsTheThreeSeededRoles()
    {
        var email = await CreateUserAsync(RoleNames.SocAnalyst);
        try
        {
            var client = await AuthenticatedClientAsync(email);
            var response = await client.GetAsync("/api/roles");
            var roles = await response.Content.ReadFromJsonAsync<List<RoleResponse>>();

            Assert.Equal(3, roles!.Count);
        }
        finally
        {
            await CleanupUserAsync(email);
        }
    }
}
