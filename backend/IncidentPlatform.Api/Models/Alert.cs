namespace IncidentPlatform.Api.Models;

public enum AlertSource
{
    Siem,
    Edr,
    Firewall,
    Ids,
    EmailSecurity,
    Manual,

    /// <summary>
    /// Findings from an authorized offensive-security tool (e.g. HexStrike
    /// AI on an isolated Kali VM). Blue-team platform consumes red-team
    /// output as input only — no live-triggering path exists
    /// (docs/architecture.md §7).
    /// </summary>
    PenTest,
    WindowsEvent,

    /// <summary>Raised from an ingested VPN log (see Models/LogEvent.cs).</summary>
    Vpn,

    /// <summary>Raised by user/entity behavior analytics (see Services/Ueba).</summary>
    Ueba
}

public enum AlertStatus
{
    New,
    InReview,
    FalsePositive,
    Promoted,
    Closed
}

/// <summary>
/// Many-to-one into Incidents via a nullable FK (database-design.md §3.2) —
/// many alerts can point at one incident; an alert points at zero or one.
/// The reverse case (one alert belonging to two incidents) isn't a real SOC
/// workflow; two incidents needing the same alert should be merged instead.
/// </summary>
public class Alert
{
    public string? EnrichmentJson { get; set; }
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public AlertSource Source { get; set; }
    public string? SourceRuleId { get; set; }
    public string? ExternalId { get; set; }

    /// <summary>
    /// Unique — lets a SIEM/EDR connector re-send the same alert without
    /// creating a duplicate row.
    /// </summary>
    public string? DeduplicationKey { get; set; }

    public string Severity { get; set; } = string.Empty; // source-reported, free text — not our own enum
    public AlertStatus Status { get; set; }

    /// <summary>
    /// The original event, verbatim, stored as MySQL json — never parsed
    /// destructively, because alert shapes differ per vendor and change
    /// without notice. This is evidence.
    /// </summary>
    public string? RawPayload { get; set; }

    // Primary entities this alert concerns, populated at creation where known.
    // They drive correlation (grouping related alerts into one case) and UEBA linkage.
    public string? Host { get; set; }
    public string? Username { get; set; }
    public string? EntityIp { get; set; }

    public int? IncidentId { get; set; }
    public Incident? Incident { get; set; }

    public int? TriagedById { get; set; }
    public User? TriagedBy { get; set; }

    public DateTime DetectedAt { get; set; }
    public DateTime ReceivedAt { get; set; }
    public DateTime? TriagedAt { get; set; }
}
