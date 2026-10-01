using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Alerts;

public class AlertSummaryResponse
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public AlertSource Source { get; set; }
    public string Severity { get; set; } = string.Empty;
    public AlertStatus Status { get; set; }
    public int? IncidentId { get; set; }
    public DateTime DetectedAt { get; set; }
}

public class AlertDetailResponse
{
    public string? RecommendedAction { get; set; }
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public AlertSource Source { get; set; }
    public string? SourceRuleId { get; set; }
    public string Severity { get; set; } = string.Empty;
    public AlertStatus Status { get; set; }
    public string? RawPayload { get; set; }
    public int? IncidentId { get; set; }
    public DateTime DetectedAt { get; set; }
    public DateTime ReceivedAt { get; set; }
    public DateTime? TriagedAt { get; set; }
}

public class AlertCreateRequest
{
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public AlertSource Source { get; set; }
    public string Severity { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; }
    public string? RawPayload { get; set; }
}

public class PromoteAlertRequest
{
    public string Title { get; set; } = string.Empty;
    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentCategory Category { get; set; }
}

public class FalsePositiveRequest
{
    public string Reason { get; set; } = string.Empty;
}