namespace IncidentPlatform.Api.DTOs.Auth;

/// <summary>
/// Matches api-design.md §2's response shape exactly.
/// </summary>
public class LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public int ExpiresIn { get; set; } // seconds
    public LoginUserInfo User { get; set; } = null!;
}

public class LoginUserInfo
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = [];
}
