using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Workspace;
using IncidentPlatform.Api.Models;
namespace IncidentPlatform.Api.Interfaces;

public interface IWorkspaceService
{
    Task<PagedResult<AuditEntry>> Audit(int page, int pageSize, string? action, string? entityType, string? entityId, AuditOutcome? outcome, CancellationToken ct);
    Task<List<IncidentLink>> Links(int incidentId, string kind, CancellationToken ct);
}
