using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Alerts;

/// <summary>Bound from the query string of GET /api/alerts (api-design.md §5).</summary>
public class AlertQuery
{
    public const string DefaultSort = "detectedAt";
    public static readonly string[] SortKeys = ["detectedAt", "severity", "status", "source", "title"];

    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 25;
    public AlertStatus? Status { get; set; }
    public AlertSource? Source { get; set; }
    /// <summary>Source-reported severity text, matched case-insensitively.</summary>
    public string? Severity { get; set; }
    /// <summary>New and InReview only — the analyst's working queue.</summary>
    public bool OpenOnly { get; set; }
    /// <summary>Matches title, description and source rule id.</summary>
    public string? Search { get; set; }
    public DateTime? DetectedFrom { get; set; }
    public DateTime? DetectedTo { get; set; }
    public string? Sort { get; set; }
    public string? Direction { get; set; }
}

public class AlertSummaryResponse
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? SourceRuleId { get; set; }
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