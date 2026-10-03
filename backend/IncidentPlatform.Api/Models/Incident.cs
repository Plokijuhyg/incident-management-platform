namespace IncidentPlatform.Api.Models;

public enum IncidentSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public enum IncidentPriority
{
    Low,
    Medium,
    High,
    Urgent
}

/// <summary>
/// Transition rules are deliberately not designed yet (database-design.md
/// §4.3) — the state machine is its own future step. For now the column
/// accepts any value and every change is simply recorded.
/// </summary>
public enum IncidentStatus
{
    New,
    Triaged,
    Investigating,
    Contained,
    Eradicated,
    Recovering,
    Resolved,
    Closed,
    FalsePositive
}

public enum IncidentCategory
{
    Malware,
    Phishing,
    AccountCompromise,
    NetworkAttack,
    DataExfiltration,
    Ransomware,
    InsiderThreat,
    Vulnerability,
    UnauthorizedAccess,
    Other
}

public enum IncidentSource
{
    Siem,
    Edr,
    Firewall,
    Ids,
    EmailSecurity,
    Manual,
    UserReport,
    ThreatIntel,
    PenTest,
    WindowsEvent,
    Vpn,
    Ueba,
    /// <summary>Opened automatically by the correlation engine from grouped alerts.</summary>
    Correlation
}

/// <summary>
/// The central entity. Severity (how bad, technically) and Priority (what to
/// work on next) are deliberately separate columns — collapsing them forces
/// analysts to lie about one to express the other (database-design.md §4.3).
///
/// Milestone timestamps are separate nullable columns, not derived from the
/// timeline, because every dashboard metric (MTTD/MTTC/MTTR) is computed
/// from them directly — deriving them by scanning timeline events on every
/// dashboard load would be both slow and fragile.
/// </summary>
public class Incident
{
    public string? EnrichmentJson { get; set; }
    public int Id { get; set; }
    public string IncidentNumber { get; set; } = string.Empty; // "INC-2026-000042"
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentStatus Status { get; set; }
    public IncidentCategory Category { get; set; }
    public IncidentSource Source { get; set; }

    public int CreatedById { get; set; }
    public User CreatedBy { get; set; } = null!;

    public int? AssignedToId { get; set; }
    public User? AssignedTo { get; set; }

    // DetectedAt vs CreatedAt is a real distinction, not redundancy: a
    // SIEM rule can detect activity hours before a human creates the
    // record. MTTD is meaningless if these are conflated.
    public DateTime? OccurredAt { get; set; }
    public DateTime? DetectedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public DateTime? TriagedAt { get; set; }
    public DateTime? ContainedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public DateTime? ClosedAt { get; set; }

    public string? ResolutionSummary { get; set; }
    public string? FalsePositiveReason { get; set; }

    // SOC case workflow (database-design.md §4.3 extension):
    // Tier 1 = initial triage, Tier 2 = investigation, Tier 3 = IR/threat hunting.
    // Escalation raises the tier; de-escalation is not modeled.
    public int Tier { get; set; } = 1;
    public DateTime? EscalatedAt { get; set; }

    /// <summary>Response-time target, set from severity when the case opens. Used for the breach view.</summary>
    public DateTime? SlaDueAt { get; set; }

    /// <summary>
    /// For correlation-created cases: the entity key that grouped the alerts
    /// (e.g. "host:HOST01"). Lets later alerts for the same entity join the open case.
    /// </summary>
    public string? CorrelationKey { get; set; }

    /// <summary>
    /// Optimistic concurrency token. MySQL has no auto-updating binary row
    /// version like SQL Server's rowversion, so this is a plain int,
    /// configured with IsConcurrencyToken() and incremented by the service
    /// on every save. Two analysts editing the same incident: the second
    /// save gets a 409 Conflict instead of silently overwriting the first.
    /// </summary>
    public int Version { get; set; }
}
