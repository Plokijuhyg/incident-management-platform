namespace IncidentPlatform.Api.Models;

/// <summary>
/// Join entity with a composite key (UserId, RoleId) — configured in
/// UserRoleConfiguration, not here (EF Core composite keys are Fluent-API
/// only, no data-annotation equivalent).
///
/// A join table rather than a single Role column on User, because a lead
/// analyst can genuinely hold both SOC_ANALYST and SECURITY_MANAGER, and
/// because role assignment is itself a security-relevant event worth
/// attributing via AssignedById (database-design.md §4.2).
/// </summary>
public class UserRole
{
    public int UserId { get; set; }
    public User User { get; set; } = null!;

    public int RoleId { get; set; }
    public Role Role { get; set; } = null!;

    public DateTime AssignedAt { get; set; }

    public int AssignedById { get; set; }
    public User AssignedBy { get; set; } = null!;
}
