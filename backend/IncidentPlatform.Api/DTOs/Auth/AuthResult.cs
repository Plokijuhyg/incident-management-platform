namespace IncidentPlatform.Api.DTOs.Auth;

/// <summary>
/// Internal contract between AuthService and AuthController — never
/// serialized directly to the client. The controller extracts
/// RawRefreshToken to set the HttpOnly cookie and returns only
/// LoginResponse in the JSON body, per api-design.md §2 (the refresh token
/// is delivered as a cookie, never in the response body).
/// </summary>
public class AuthResult
{
    public LoginResponse LoginResponse { get; set; } = null!;
    public string RawRefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiresAt { get; set; }
}