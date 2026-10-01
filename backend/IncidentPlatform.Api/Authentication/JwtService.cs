using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IncidentPlatform.Api.Authentication;

public class JwtService : IJwtService
{
    private readonly JwtSettings _settings;

    public JwtService(IOptions<JwtSettings> settings)
    {
        _settings = settings.Value;
    }

    public string GenerateAccessToken(User user, IReadOnlyList<string> roleNames)
    {
        var claims = new List<Claim>
        {
            // Sub + NameIdentifier both carry the user id: Sub is the JWT-
            // standard claim; NameIdentifier is what ASP.NET Core's
            // [Authorize] and User.Identity conventionally read from.
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Name, user.FullName),
            new("pwdv", Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash)))),

            // A unique token identifier — not used for anything yet, but
            // standard practice, and useful later if token revocation by
            // jti is ever needed.
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // One claim per role, using ClaimTypes.Role specifically — this is
        // the claim type ASP.NET Core's [Authorize(Roles = "...")] and
        // role-based policies read from by convention.
        claims.AddRange(roleNames.Select(role => new Claim(ClaimTypes.Role, role)));

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.AccessTokenExpirationMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
