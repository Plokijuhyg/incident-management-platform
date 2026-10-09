using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace IncidentPlatform.Api.Controllers;

[ApiController, Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}")]
public sealed class WorkspaceController(IWorkspaceService service) : ControllerBase
{
    [HttpGet("api/audit-logs"), Authorize(Roles = RoleNames.Admin)]
    public async Task<IActionResult> Audit(int page = 1, int pageSize = 25, string? action = null, string? entityType = null, string? entityId = null, AuditOutcome? outcome = null, CancellationToken ct = default)
     => Ok(await service.Audit(page, pageSize, action, entityType, entityId, outcome, ct));
    [HttpGet("api/audit-logs/entity/{entityType}/{entityId}"), Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager}")]
    public async Task<IActionResult> EntityAudit(string entityType, string entityId, int page = 1, int pageSize = 25, CancellationToken ct = default)
     => Ok(await service.Audit(page, pageSize, null, entityType, entityId, null, ct));
    [HttpGet("api/incidents/{id:int}/iocs")]
    public async Task<IActionResult> Iocs(int id, CancellationToken ct) => Ok(await service.Links(id, "iocs", ct));
    [HttpGet("api/incidents/{id:int}/assets")]
    public async Task<IActionResult> Assets(int id, CancellationToken ct) => Ok(await service.Links(id, "assets", ct));
    [HttpGet("api/incidents/{id:int}/mitre-techniques")]
    public async Task<IActionResult> Mitre(int id, CancellationToken ct) => Ok(await service.Links(id, "mitre-techniques", ct));
}
