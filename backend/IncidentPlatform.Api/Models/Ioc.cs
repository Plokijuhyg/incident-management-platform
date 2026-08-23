namespace IncidentPlatform.Api.Models;

public enum IocType
{
    IpAddress,
    Domain,
    Url,
    HashMd5,
    HashSha1,
    HashSha256,
    Email,
    FileName,
    RegistryKey,
    UserAgent
}

public enum IocConfidence
{
    Low,
    Medium,
    High,
    Confirmed
}

/// <summary>
/// The global, deduplicated IOC catalog (database-design.md §3.1) — the
/// entire analytical value of IOC tracking is "have we seen this before?",
/// which only a UNIQUE (Type, Value) catalog can answer as a single row
/// lookup instead of a string scan across every incident.
///
/// Normalisation (lowercasing, defanging removal) happens in the *service*
/// layer on write — not here. This entity stores whatever value it's given;
/// enforcing the unique constraint is the database's job, producing a
/// correctly normalised value before that constraint is checked is the
/// service's job. RawValue preserves the original input for provenance.
/// </summary>
public class Ioc
{
    public int Id { get; set; }
    public IocType Type { get; set; }
    public string Value { get; set; } = string.Empty;
    public string? RawValue { get; set; }
    public IocConfidence Confidence { get; set; }

    /// <summary>
    /// Deliberately nullable: null = unverified. A non-nullable bool would
    /// force every unreviewed indicator to claim it's benign, which is
    /// exactly backwards for a security tool (database-design.md §4.5).
    /// </summary>
    public bool? IsMalicious { get; set; }

    public string? Source { get; set; }
    public string? Description { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }

    /// <summary>
    /// Denormalised counter, maintained by the service in the same
    /// transaction as each new sighting link — avoids aggregating the join
    /// table on every "top IOCs" dashboard load.
    /// </summary>
    public int SightingCount { get; set; }

    public int CreatedById { get; set; }
    public User CreatedBy { get; set; } = null!;

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
