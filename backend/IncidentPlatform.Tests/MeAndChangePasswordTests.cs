using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class MeAndChangePasswordTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public MeAndChangePasswordTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private async Task<string> CreateTestUserAsync(string password)
    {
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

        var email = $"test-{Guid.NewGuid():N}@example.com";

        dbContext.Users.Add(new User
        {
            Email = email,
            FullName = "Test User",
            PasswordHash = hasher.Hash(password),
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });

        await dbContext.SaveChangesAsync();
        return email;
    }

    private async Task DeleteTestUserAsync(string email)
    {
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        var user = dbContext.Users.SingleOrDefault(u => u.Email == email);
        if (user is not null)
        {
            var tokens = dbContext.RefreshTokens.Where(t => t.UserId == user.Id);
            dbContext.RefreshTokens.RemoveRange(tokens);
            dbContext.Users.Remove(user);
            await dbContext.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task Me_WithoutToken_Returns401()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_WithValidToken_ReturnsCorrectUserInfo()
    {
        var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

        try
        {
            var client = _factory.CreateClient();

            var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "CorrectHorseBatteryStaple"
            });
            var loginBody = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

            var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginBody!.AccessToken);

            var meResponse = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

            var meBody = await meResponse.Content.ReadFromJsonAsync<MeResponse>();
            Assert.Equal(email, meBody!.Email);
        }
        finally
        {
            await DeleteTestUserAsync(email);
        }
    }

    [Fact]
    public async Task ChangePassword_WithWrongCurrentPassword_Returns400()
    {
        var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

        try
        {
            var client = _factory.CreateClient();

            var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "CorrectHorseBatteryStaple"
            });
            var loginBody = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

            var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/change-password")
            {
                Content = JsonContent.Create(new ChangePasswordRequest
                {
                    CurrentPassword = "WrongPassword",
                    NewPassword = "NewPassword123!"
                })
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginBody!.AccessToken);

            var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        finally
        {
            await DeleteTestUserAsync(email);
        }
    }

    [Fact]
    public async Task ChangePassword_WithCorrectCurrentPassword_AllowsLoginWithNewPasswordAndRevokesOldRefreshToken()
    {
        var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

        try
        {
            var client = _factory.CreateClient();

            var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "CorrectHorseBatteryStaple"
            });
            var loginBody = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

            var changeRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/change-password")
            {
                Content = JsonContent.Create(new ChangePasswordRequest
                {
                    CurrentPassword = "CorrectHorseBatteryStaple",
                    NewPassword = "NewPassword123!"
                })
            };
            changeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", loginBody!.AccessToken);

            var changeResponse = await client.SendAsync(changeRequest);
            Assert.Equal(HttpStatusCode.NoContent, changeResponse.StatusCode);

            // Old refresh token cookie was set by the login call above and
            // is stored in this client's cookie container — it must now be
            // rejected, since change-password revokes all active sessions.
            var refreshResponse = await client.PostAsync("/api/auth/refresh", null);
            Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse.StatusCode);

            // Old password no longer works.
            var oldLoginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "CorrectHorseBatteryStaple"
            });
            Assert.Equal(HttpStatusCode.Unauthorized, oldLoginResponse.StatusCode);

            // New password works.
            var newLoginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "NewPassword123!"
            });
            Assert.Equal(HttpStatusCode.OK, newLoginResponse.StatusCode);
        }
        finally
        {
            await DeleteTestUserAsync(email);
        }
    }
}
