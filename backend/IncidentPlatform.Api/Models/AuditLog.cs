namespace IncidentPlatform.Api.Models;

public enum AuditOutcome
{
    Success,
    Failure,

    /// <summary>
    /// A rejected authorization attempt is a security signal — "an analyst
    /// tried to reach an incident they don't own" — not an ordinary error.
    /// Kept distinct from Failure specifically because these are the
    /// entries worth alerting on (database-design.md §4.12).
    /// </summary>
    Denied
}

/// <summary>
/// Append-only. No update or delete path exists anywhere in the
/// application — that's the actual mechanism that makes this an audit log;
/// nothing in the schema itself prevents a row from being modified.
///
/// ActorEmail is a deliberate denormalized snapshot, not redundancy: an
/// entry must stay meaningful in isolation years later even if the user
/// record is later renamed (database-design.md §4.12).
/// </summary>
public class AuditLog
{
    public long Id { get; set; } // bigint — this table outgrows every other by orders of magnitude

    public int? ActorUserId { get; set; }
    public User? ActorUser { get; set; }

    public string? ActorEmail { get; set; }

    public string Action { get; set; } = string.Empty; // e.g. "INCIDENT_CREATED", "LOGIN_FAILED"
    public string? EntityType { get; set; }
    public string? EntityId { get; set; } // string, not int — can reference any entity's key

    public AuditOutcome Outcome { get; set; }

    public string IpAddress { get; set; } = string.Empty;
    public string? UserAgent { get; set; }

    /// <summary>
    /// Changed fields, before/after — never secrets or file contents
    /// (database-design.md §4.12).
    /// </summary>
    public string? Details { get; set; } // MySQL json

    public DateTime OccurredAt { get; set; }
}
