using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Xunit;

namespace IncidentPlatform.Tests;

public class JwtServiceTests
{
    private static JwtService CreateService(int expirationMinutes = 15)
    {
        var settings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-that-is-long-enough-for-hs256",
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenExpirationMinutes = expirationMinutes
        };

        return new JwtService(Options.Create(settings));
    }

    private static User CreateTestUser() => new()
    {
        Id = 7,
        Email = "analyst@soc.local",
        FullName = "Sam Okafor",
        PasswordHash = "irrelevant-for-this-test",
        CreatedAt = DateTime.UtcNow,
        UpdatedAt = DateTime.UtcNow
    };

    [Fact]
    public void GenerateAccessToken_ProducesAWellFormedJwt()
    {
        var service = CreateService();
        var token = service.GenerateAccessToken(CreateTestUser(), [RoleNames.SocAnalyst]);

        // A JWT is three base64url segments separated by dots.
        Assert.Equal(3, token.Split('.').Length);
    }

    [Fact]
    public void GenerateAccessToken_EmbedsCorrectUserClaims()
    {
        var service = CreateService();
        var token = service.GenerateAccessToken(CreateTestUser(), [RoleNames.SocAnalyst]);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        Assert.Equal("7", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal("analyst@soc.local", jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value);
        Assert.Equal(RoleNames.SocAnalyst, jwt.Claims.First(c => c.Type == ClaimTypes.Role).Value);
    }

    [Fact]
    public void GenerateAccessToken_WithMultipleRoles_EmbedsAllOfThem()
    {
        var service = CreateService();
        var token = service.GenerateAccessToken(
            CreateTestUser(),
            [RoleNames.SocAnalyst, RoleNames.SecurityManager]);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        var roleClaims = jwt.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();

        Assert.Contains(RoleNames.SocAnalyst, roleClaims);
        Assert.Contains(RoleNames.SecurityManager, roleClaims);
    }

    [Fact]
    public void GenerateAccessToken_IsSignedWithTheConfiguredSecret_AndValidatesSuccessfully()
    {
        var secret = "this-is-a-test-secret-that-is-long-enough-for-hs256";
        var settings = new JwtSettings
        {
            Secret = secret,
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            AccessTokenExpirationMinutes = 15
        };

        var service = new JwtService(Options.Create(settings));
        var token = service.GenerateAccessToken(CreateTestUser(), [RoleNames.SocAnalyst]);

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = "TestIssuer",
            ValidAudience = "TestAudience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true
        };

        // This is the real proof: an independent validator, configured with
        // the same secret, must accept the token. If someone weakens the
        // signing algorithm or key later, this test breaks immediately.
        var principal = new JwtSecurityTokenHandler()
            .ValidateToken(token, validationParameters, out _);

        Assert.NotNull(principal);
    }

    [Fact]
    public void GenerateAccessToken_ExpiresAtTheConfiguredTime()
    {
        var service = CreateService(expirationMinutes: 5);
        var token = service.GenerateAccessToken(CreateTestUser(), [RoleNames.SocAnalyst]);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);

        var expectedExpiry = DateTime.UtcNow.AddMinutes(5);
        // A few seconds of tolerance for test execution time — not exact-
        // millisecond matching, which would make this test flaky.
        Assert.True(Math.Abs((jwt.ValidTo - expectedExpiry).TotalSeconds) < 5);
    }
}
