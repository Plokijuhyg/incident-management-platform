using System.Text.Json;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services.Ingestion;

/// <summary>
/// Deterministic review signals over a normalized <see cref="LogEvent"/>. Like
/// the Windows rules, a match is a triage priority, not proof of compromise.
/// One alert per event (highest-priority rule wins); thresholded/correlated
/// detections across many events are a later increment.
/// </summary>
public static class IngestionRules
{
    public static Alert? Evaluate(LogEvent e)
    {
        // 1. Enrichment-driven: traffic touching a known-malicious indicator.
        if (e.Enriched && e.EnrichmentJson is not null)
            return Build(e, "LOG-IOC-MATCH", "High",
                "Log event references a known-malicious indicator",
                e.SourceType == LogSourceType.Firewall ? AlertSource.Firewall : AlertSource.Siem);

        // 2. VPN authentication failure — the brute-force / credential-stuffing starting point.
        if (e.SourceType == LogSourceType.Vpn && e.Outcome == "failure" && IsAuth(e.Action))
            return Build(e, "VPN-AUTH-FAILURE", "Medium",
                "VPN authentication failure", AlertSource.Vpn);

        // 3. Critical-or-worse syslog severity (emergency/alert/critical).
        if (e.Severity <= 2)
            return Build(e, "LOG-CRITICAL-SEVERITY", "Medium",
                $"Critical-severity log event ({SeverityName(e.Severity)})",
                e.SourceType == LogSourceType.Firewall ? AlertSource.Firewall : AlertSource.Siem);

        return null;
    }

    private static bool IsAuth(string? action) =>
        action is not null && (action.Contains("login") || action.Contains("logon") ||
            action.Contains("auth") || action.Contains("connect"));

    private static string SeverityName(int severity) => severity switch
    {
        0 => "emergency", 1 => "alert", 2 => "critical", 3 => "error",
        4 => "warning", 5 => "notice", 6 => "info", _ => "debug"
    };

    private static Alert Build(LogEvent e, string ruleId, string severity, string title, AlertSource source) => new()
    {
        Title = title,
        Description = "Ingested log matched a review rule. Severity is a triage priority, not proof of compromise. " +
                      "Review the original log line and context before promoting to an incident.",
        Source = source,
        SourceRuleId = ruleId,
        DeduplicationKey = "log:" + ruleId + ":" + e.Fingerprint,
        Host = e.Host,
        Username = e.User,
        EntityIp = e.SourceIp,
        Severity = severity,
        Status = AlertStatus.New,
        DetectedAt = e.EventTime,
        ReceivedAt = e.ReceivedAt,
        EnrichmentJson = e.EnrichmentJson,
        RawPayload = JsonSerializer.Serialize(new
        {
            e.Source, sourceType = e.SourceType.ToString(), e.Host, e.EventTime, e.Severity,
            e.Action, e.Outcome, e.SourceIp, e.DestinationIp, e.SourcePort, e.DestinationPort,
            e.Protocol, e.User, e.Message, logFingerprint = e.Fingerprint, rule = ruleId, raw = e.RawLog
        })
    };
}
