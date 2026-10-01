using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Mapping;

public static class IncidentMapper
{
    public static IncidentDetailResponse ToDetailResponse(Incident i) => new()
    {
        Id = i.Id,
        IncidentNumber = i.IncidentNumber,
        Title = i.Title,
        Description = i.Description,
        Severity = i.Severity,
        Priority = i.Priority,
        Status = i.Status,
        Category = i.Category,
        Source = i.Source,
        CreatedById = i.CreatedById,
        CreatedByName = i.CreatedBy?.FullName ?? string.Empty,
        AssignedToId = i.AssignedToId,
        AssignedToName = i.AssignedTo?.FullName,
        OccurredAt = i.OccurredAt,
        DetectedAt = i.DetectedAt,
        CreatedAt = i.CreatedAt,
        UpdatedAt = i.UpdatedAt,
        TriagedAt = i.TriagedAt,
        ContainedAt = i.ContainedAt,
        ResolvedAt = i.ResolvedAt,
        ClosedAt = i.ClosedAt,
        ResolutionSummary = i.ResolutionSummary,
        Version = i.Version
    };
}