namespace IncidentPlatform.Api.Models;

/// <summary>
/// Where an ingested log came from, after normalization. Firewall and VPN keep
/// their own type so detection and the UI can treat them specially; everything
/// else that is syslog- or JSON-shaped lands as Generic.
/// </summary>
public enum LogSourceType
{
    Generic,
    Syslog,
    Firewall,
    Vpn,
    Api
}

/// <summary>
/// How the caller says a batch is framed, which picks the parser. Firewall and
/// VPN are syslog/key-value underneath but apply their own field mapping.
/// </summary>
public enum LogFormat
{
    Syslog,
    Firewall,
    Vpn,
    Json,
    KeyValue
}

/// <summary>
/// A single ingested log line after Raw → Parse → Normalize → Enrich. One common
/// schema across every non-Windows source so they share a UTC timeline, the same
/// detection path and one query surface. The original line is kept verbatim in
/// <see cref="RawLog"/> as evidence; parsing is never destructive.
/// </summary>
public sealed class LogEvent
{
    public long Id { get; set; }

    /// <summary>SHA-256 of source + raw line; unique, so re-sent lines deduplicate.</summary>
    public string Fingerprint { get; set; } = "";

    /// <summary>Caller-supplied source name, e.g. "edge-firewall" or "vpn-gw-1".</summary>
    public string Source { get; set; } = "";
    public LogSourceType SourceType { get; set; }

    /// <summary>Device/host that emitted the line (from the syslog header or a host field).</summary>
    public string? Host { get; set; }

    /// <summary>Event time from the log itself, normalized to UTC. Falls back to ReceivedAt.</summary>
    public DateTime EventTime { get; set; }
    /// <summary>When the platform ingested the line (UTC).</summary>
    public DateTime ReceivedAt { get; set; }

    /// <summary>Normalized syslog severity: 0 Emergency … 7 Debug. Lower is worse.</summary>
    public int Severity { get; set; } = 6;
    public string? Facility { get; set; }

    public string? Action { get; set; }   // allow / deny / connect / login …
    public string? Outcome { get; set; }   // success / failure
    public string? SourceIp { get; set; }
    public string? DestinationIp { get; set; }
    public int? SourcePort { get; set; }
    public int? DestinationPort { get; set; }
    public string? Protocol { get; set; }
    public string? User { get; set; }

    public string Message { get; set; } = "";
    public string RawLog { get; set; } = "";

    /// <summary>Remaining parsed key/values that have no dedicated column, as JSON.</summary>
    public string? FieldsJson { get; set; }

    public bool Enriched { get; set; }
    /// <summary>Threat-intel and other enrichment results, as JSON. Evidence, not parsed back.</summary>
    public string? EnrichmentJson { get; set; }

    public int? AlertId { get; set; }
}
