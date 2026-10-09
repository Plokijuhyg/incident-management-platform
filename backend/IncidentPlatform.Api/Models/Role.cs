namespace IncidentPlatform.Api.Models;

/// <summary>
/// Roles are seeded reference data, not user-creatable — per
/// database-design.md §4.2, the API exposes no "create role" endpoint,
/// since authorization policies are written against these known names.
/// </summary>
public class Role
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}

/// <summary>
/// The three seeded role names, as string constants rather than a C# enum.
/// Kept as constants (not an enum persisted via HasConversion) because Roles
/// is a real table with its own Id/Description — these strings are used when
/// seeding that table and when writing [Authorize(Roles = ...)] policies,
/// not as a column type.
/// </summary>
public static class RoleNames
{
    public const string Admin = "ADMIN";
    public const string SecurityManager = "SECURITY_MANAGER";
    public const string SocAnalyst = "SOC_ANALYST";

    /// <summary>
    /// Red-team identity for the two-laptop lab: authorized ONLY on the Assessments
    /// module (target/tool selection, triggering scans, viewing its own results and
    /// their LLM analysis). Explicitly excluded from every blue-team/SOC endpoint —
    /// those controllers enumerate the blue roles, so RED_TEAM is denied (403).
    /// </summary>
    public const string RedTeam = "RED_TEAM";
}
