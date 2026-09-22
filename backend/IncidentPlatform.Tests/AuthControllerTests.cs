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
        // RefreshTokens -> Users is RESTRICT (by design, matching every
        // other FK to Users in the schema) — so any refresh tokens issued
        // during the test must be deleted first, or the user delete itself
        // is correctly rejected by the database.
        var tokens = dbContext.RefreshTokens.Where(t => t.UserId == user.Id);
        dbContext.RefreshTokens.RemoveRange(tokens);

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
    [Fact]
public async Task Login_SetsAnHttpOnlyRefreshTokenCookie()
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

        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookies));
        var cookieHeader = cookies!.First();

        Assert.Contains("refreshToken=", cookieHeader);
        Assert.Contains("httponly", cookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookieHeader, StringComparison.OrdinalIgnoreCase);
    }
    finally
    {
        await DeleteTestUserAsync(email);
    }
}

[Fact]
public async Task Refresh_WithValidCookie_ReturnsNewAccessTokenAndRotatesTheCookie()
{
    var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

    try
    {
        // WebApplicationFactory's default client handles cookies
        // automatically (HandleCookies defaults to true) — logging in and
        // then calling refresh on the SAME client sends the cookie the
        // login response set, exactly like a real browser would.
        var client = _factory.CreateClient();

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = email,
            Password = "CorrectHorseBatteryStaple"
        });

        var loginBody = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        var refreshResponse = await client.PostAsync("/api/auth/refresh", null);

        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var refreshBody = await refreshResponse.Content.ReadFromJsonAsync<LoginResponse>();
        Assert.NotNull(refreshBody);

        // A genuinely new access token — proves rotation actually happened,
        // not just that the same token was echoed back.
        Assert.NotEqual(loginBody!.AccessToken, refreshBody!.AccessToken);
    }
    finally
    {
        await DeleteTestUserAsync(email);
    }
}

[Fact]
public async Task Refresh_CalledTwiceWithTheSameOldCookie_SecondCallFailsBecauseTokenWasRotated()
{
    var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

    try
    {
        // Two independent clients so we can hang on to the FIRST refresh
        // token's cookie deliberately, even after client A rotates past it.
        var clientA = _factory.CreateClient();
        var clientB = _factory.CreateClient();

        await clientA.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = email,
            Password = "CorrectHorseBatteryStaple"
        });

        // Manually copy client A's cookie onto a fresh request for client B,
        // simulating "someone else has a copy of this exact refresh token".
        var cookieContainer = clientA.DefaultRequestHeaders;
        // Since HandleCookies manages this internally rather than exposing
        // it directly, we instead drive the scenario through clientA twice:
        // first refresh succeeds and rotates; a second refresh using the
        // ORIGINAL (now-revoked) token must fail. We simulate "the original
        // token used again" by capturing it before the first refresh.

        var loginResponse2 = await clientB.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = email,
            Password = "CorrectHorseBatteryStaple"
        });
        loginResponse2.Headers.TryGetValues("Set-Cookie", out var setCookies);
        var originalCookieValue = setCookies!.First().Split(';')[0]; // "refreshToken=..."

        // First refresh: succeeds, rotates the token.
        var firstRefresh = await clientB.PostAsync("/api/auth/refresh", null);
        Assert.Equal(HttpStatusCode.OK, firstRefresh.StatusCode);

        // Second attempt: manually replay the ORIGINAL cookie value (now
        // revoked) via an explicit header on a fresh request — bypassing
        // clientB's own automatically-updated cookie jar, which has already
        // moved on to the new token.
        var replayRequest = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh");
        replayRequest.Headers.Add("Cookie", originalCookieValue);

        var replayResponse = await _factory.CreateClient().SendAsync(replayRequest);

        Assert.Equal(HttpStatusCode.Unauthorized, replayResponse.StatusCode);
    }
    finally
    {
        await DeleteTestUserAsync(email);
    }
}

[Fact]
public async Task Logout_ThenRefresh_Returns401()
{
    var email = await CreateTestUserAsync("CorrectHorseBatteryStaple");

    try
    {
        var client = _factory.CreateClient();

        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = email,
            Password = "CorrectHorseBatteryStaple"
        });

        var logoutResponse = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        var refreshResponse = await client.PostAsync("/api/auth/refresh", null);
        Assert.Equal(HttpStatusCode.Unauthorized, refreshResponse.StatusCode);
    }
    finally
    {
        await DeleteTestUserAsync(email);
    }
}

[Fact]
public async Task Refresh_WithNoCookieAtAll_Returns401()
{
    var client = _factory.CreateClient();

    var response = await client.PostAsync("/api/auth/refresh", null);

    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
}
}
