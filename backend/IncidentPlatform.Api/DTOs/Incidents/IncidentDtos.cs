using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Incidents;

/// <summary>Bound from the query string of GET /api/incidents (api-design.md §3).</summary>
public class IncidentQuery
{
    public const string DefaultSort = "createdAt";
    public static readonly string[] SortKeys = ["createdAt", "updatedAt", "severity", "priority", "status", "title", "incidentNumber"];

    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 25;
    public IncidentStatus? Status { get; set; }
    public IncidentSeverity? Severity { get; set; }
    public IncidentPriority? Priority { get; set; }
    public IncidentCategory? Category { get; set; }
    public IncidentSource? Source { get; set; }
    public int? AssignedToId { get; set; }
    public bool Unassigned { get; set; }
    public int? Tier { get; set; }
    /// <summary>Open cases past their SLA target.</summary>
    public bool SlaBreached { get; set; }
    /// <summary>Excludes Resolved, Closed and FalsePositive (same definition as the dashboard).</summary>
    public bool OpenOnly { get; set; }
    /// <summary>Matches title, incident number and description.</summary>
    public string? Search { get; set; }
    public DateTime? CreatedFrom { get; set; }
    public DateTime? CreatedTo { get; set; }
    public string? Sort { get; set; }
    public string? Direction { get; set; }
}

/// <summary>
/// Summary projection for list endpoints — api-design.md §3: no
/// descriptions, no child collections, selected via .Select() so the SQL
/// fetches only these columns.
/// </summary>
public class IncidentSummaryResponse
{
    public int Id { get; set; }
    public string IncidentNumber { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentStatus Status { get; set; }
    public IncidentCategory Category { get; set; }
    public string? AssignedToName { get; set; }
    public int Tier { get; set; }
    public DateTime? SlaDueAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed record RecommendedResponse(int AlertId, string? RuleId, string Text);

public class IncidentDetailResponse
{
    public List<RecommendedResponse> RecommendedActions { get; set; } = [];
    public int Id { get; set; }
    public string IncidentNumber { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentStatus Status { get; set; }
    public IncidentCategory Category { get; set; }
    public IncidentSource Source { get; set; }
    public int CreatedById { get; set; }
    public string CreatedByName { get; set; } = string.Empty;
    public int? AssignedToId { get; set; }
    public string? AssignedToName { get; set; }
    public DateTime? OccurredAt { get; set; }
    public DateTime? DetectedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? TriagedAt { get; set; }
    public DateTime? ContainedAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public DateTime? ClosedAt { get; set; }
    public string? ResolutionSummary { get; set; }
    public int Tier { get; set; }
    public DateTime? EscalatedAt { get; set; }
    public DateTime? SlaDueAt { get; set; }
    public string? CorrelationKey { get; set; }
    public int Version { get; set; }
}

public sealed class EscalateIncidentRequest
{
    public int Tier { get; set; }
    public int? AssignedToId { get; set; }
    public string? Note { get; set; }
}

public class IncidentCreateRequest
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentCategory Category { get; set; }
    public IncidentSource Source { get; set; }
    public DateTime? OccurredAt { get; set; }
    public DateTime? DetectedAt { get; set; }
}

/// <summary>
/// Requires the Version field from the last GET — a mismatch means someone
/// else modified the incident since, and returns 409 (api-design.md §3).
/// </summary>
public class IncidentUpdateRequest
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IncidentSeverity Severity { get; set; }
    public IncidentPriority Priority { get; set; }
    public IncidentCategory Category { get; set; }
    public int Version { get; set; }
}

public class AssignIncidentRequest
{
    public int AssignedToId { get; set; }
}

public class ChangeStatusRequest
{
    public IncidentStatus Status { get; set; }
    public string? Note { get; set; }
}

public class CloseIncidentRequest
{
    public string ResolutionSummary { get; set; } = string.Empty;
}
