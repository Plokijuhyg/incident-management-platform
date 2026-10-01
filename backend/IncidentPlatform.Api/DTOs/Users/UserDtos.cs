namespace IncidentPlatform.Api.DTOs.Users;

public class UserResponse
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string? JobTitle { get; set; }
    public bool IsActive { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public List<string> Roles { get; set; } = [];
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Slim projection for assignee dropdowns — api-design.md §6: no PII beyond
/// id + name, so populating a dropdown doesn't require full admin user
/// list permission.
/// </summary>
public class AssignableUserResponse
{
    public int Id { get; set; }
    public string FullName { get; set; } = string.Empty;
}

public class CreateUserRequest
{
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? JobTitle { get; set; }
    public List<string> Roles { get; set; } = [];
}

public class UpdateUserRequest
{
    public string FullName { get; set; } = string.Empty;
    public string? JobTitle { get; set; }
}

public class ReplaceRolesRequest
{
    public List<string> Roles { get; set; } = [];
}

public class RoleResponse
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
}

public sealed record ResetUserPasswordRequest(string Password);
