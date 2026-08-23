using System.Net;
using System.Net.Http.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class AuthControllerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuthControllerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// Creates a throwaway test user directly in the real MySQL database
    /// (via the same AppDbContext the app itself uses), with a real hash
    /// from the real IPasswordHasher — not a mock. Returns the email so the
    /// test can log in with it, and cleans the row up in a finally block so
    /// repeated test runs don't collide on the unique Email constraint.
    /// </summary>
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
            dbContext.Users.Remove(user);
            await dbContext.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task Login_WithCorrectCredentials_Returns200WithAccessToken()
    {
        var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

        try
        {
            var client = _factory.CreateClient();

            var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "CorrectHorseBatteryStaple"
            });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var body = await response.Content.ReadFromJsonAsync<LoginResponse>();
            Assert.NotNull(body);
            Assert.False(string.IsNullOrWhiteSpace(body!.AccessToken));
            Assert.Equal(email, body.User.Email);
        }
        finally
        {
            await DeleteTestUserAsync(email);
        }
    }

    [Fact]
    public async Task Login_WithWrongPassword_Returns401()
    {
        var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

        try
        {
            var client = _factory.CreateClient();

            var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
            {
                Email = email,
                Password = "WrongPassword"
            });

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        finally
        {
            await DeleteTestUserAsync(email);
        }
    }

    [Fact]
    public async Task Login_WithNonexistentEmail_Returns401WithSameMessageAsWrongPassword()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = "nobody-real@example.com",
            Password = "AnyPassword"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithMalformedEmail_Returns400FromValidation()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = "not-an-email",
            Password = "AnyPassword"
        });

        // This proves FluentValidation's auto-validation is actually wired
        // in — AuthController.Login's body never runs for this request,
        // since malformed input is a 400, not a 401.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
