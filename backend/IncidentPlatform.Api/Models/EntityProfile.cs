namespace IncidentPlatform.Api.Models;

/// <summary>
/// A rolling behavioral baseline for one entity (a user or a host), built by the
/// UEBA engine from ingested logs. Deliberately simple and explainable: counts and
/// a seen-set, not a black-box model. Anomalies are deviations from this baseline
/// (a failed-login spike, a login from a never-before-seen source), which the engine
/// raises as alerts that then feed correlation.
/// </summary>
public sealed class EntityProfile
{
    public long Id { get; set; }

    public string EntityType { get; set; } = "";   // "user" | "host"
    public string EntityValue { get; set; } = "";

    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public long EventCount { get; set; }

    /// <summary>Failed logins counted in the current rolling hour window.</summary>
    public int FailedLoginsHour { get; set; }
    public DateTime WindowStart { get; set; }

    /// <summary>Distinct source IPs seen for this entity (JSON array, capped).</summary>
    public string KnownSourceIpsJson { get; set; } = "[]";

    /// <summary>Highest recent anomaly score (0..100), for the UEBA risk ranking.</summary>
    public int RiskScore { get; set; }
    public string? LastAnomaly { get; set; }
    public DateTime? LastAnomalyAt { get; set; }

    /// <summary>Processing cursor: the last LogEvent id folded into this baseline.</summary>
    public long LastEventId { get; set; }

    public DateTime UpdatedAt { get; set; }
}
