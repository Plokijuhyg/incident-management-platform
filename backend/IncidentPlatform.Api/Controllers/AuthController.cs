using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Authorization;
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
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
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

    [HttpGet("me")]
    [Authorize]
    public ActionResult<MeResponse> Me()
    {
        var userId = GetCurrentUserId();

        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? string.Empty;         var fullName = User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

        return Ok(new MeResponse
        {
            Id = userId,
            Email = email,
            FullName = fullName,
            Roles = roles
        });
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        var userId = GetCurrentUserId();
        await _authService.ChangePasswordAsync(userId, request, GetClientIp(), cancellationToken);
        return NoContent();
    }

    private int GetCurrentUserId()
    {
        var idClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (idClaim is null || !int.TryParse(idClaim, out var userId))
        {
            throw new AuthenticationFailedException();
        }

        return userId;
    }

    private void AppendRefreshTokenCookie(string rawToken, DateTime expiresAt)
    {
        Response.Cookies.Append(RefreshTokenCookieName, rawToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = !_environment.IsDevelopment(),
            SameSite = SameSiteMode.Strict,
            Expires = expiresAt,
            Path = "/api/auth"
        });
    }

    private string GetClientIp() =>
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
