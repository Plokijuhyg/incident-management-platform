using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services;

/// <summary>
/// SOC case helpers shared by every incident-creation path: the response-time
/// SLA target per severity, and mapping an alert's free-text severity onto the
/// incident severity scale.
/// </summary>
public static class CaseSla
{
    public static DateTime DueAt(IncidentSeverity severity, DateTime from) => from.Add(severity switch
    {
        IncidentSeverity.Critical => TimeSpan.FromHours(1),
        IncidentSeverity.High => TimeSpan.FromHours(4),
        IncidentSeverity.Medium => TimeSpan.FromHours(24),
        _ => TimeSpan.FromHours(72),
    });

    public static IncidentSeverity SeverityFrom(string? alertSeverity) => alertSeverity?.Trim().ToLowerInvariant() switch
    {
        "critical" => IncidentSeverity.Critical,
        "high" => IncidentSeverity.High,
        "medium" => IncidentSeverity.Medium,
        _ => IncidentSeverity.Low,
    };

    public static IncidentPriority PriorityFrom(IncidentSeverity severity) => severity switch
    {
        IncidentSeverity.Critical => IncidentPriority.Urgent,
        IncidentSeverity.High => IncidentPriority.High,
        IncidentSeverity.Medium => IncidentPriority.Medium,
        _ => IncidentPriority.Low,
    };
}
