using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private const string RefreshTokenCookieName = "refreshToken";

    private readonly IAuthService _authService;
    private readonly IWebHostEnvironment _environment;

    public AuthController(IAuthService authService, IWebHostEnvironment environment)
    {
        _authService = authService;
        _environment = environment;
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken)
    {
        var result = await _authService.LoginAsync(request, GetClientIp(), cancellationToken);
        AppendRefreshTokenCookie(result.RawRefreshToken, result.RefreshTokenExpiresAt);
        return Ok(result.LoginResponse);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<LoginResponse>> Refresh(CancellationToken cancellationToken)
    {
        var rawToken = Request.Cookies[RefreshTokenCookieName];

        if (string.IsNullOrEmpty(rawToken))
        {
            // No cookie at all is the same generic 401 as an invalid one —
            // nothing is gained by telling the caller which case applies.
            throw new AuthenticationFailedException();
        }

        var result = await _authService.RefreshAsync(rawToken, GetClientIp(), cancellationToken);
        AppendRefreshTokenCookie(result.RawRefreshToken, result.RefreshTokenExpiresAt);
        return Ok(result.LoginResponse);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        var rawToken = Request.Cookies[RefreshTokenCookieName];

        if (!string.IsNullOrEmpty(rawToken))
        {
            await _authService.LogoutAsync(rawToken, GetClientIp(), cancellationToken);
        }

        Response.Cookies.Delete(RefreshTokenCookieName, new CookieOptions { Path = "/api/auth" });

        return NoContent();
    }

    private void AppendRefreshTokenCookie(string rawToken, DateTime expiresAt)
    {
        Response.Cookies.Append(RefreshTokenCookieName, rawToken, new CookieOptions
        {
            HttpOnly = true,

            // Secure means "HTTPS only". Local dev runs on plain HTTP
            // (http://localhost:5230), so forcing Secure=true unconditionally
            // would mean the cookie is set but the browser (or HttpClient in
            // tests) never sends it back — a silent, confusing failure.
            // Production always runs behind HTTPS, so this is safe.
            Secure = !_environment.IsDevelopment(),

            SameSite = SameSiteMode.Strict,
            Expires = expiresAt,

            // Scoped to /api/auth only — this cookie has no reason to be
            // sent on every single API request, only the auth endpoints
            // that actually consume it.
            Path = "/api/auth"
        });
    }

    private string GetClientIp() =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}