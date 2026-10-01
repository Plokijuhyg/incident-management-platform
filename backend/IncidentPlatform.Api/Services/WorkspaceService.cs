using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Workspace;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;

public sealed class WorkspaceService(AppDbContext db) : IWorkspaceService
{
    public async Task<PagedResult<AuditEntry>> Audit(int page, int pageSize, string? action, string? entityType, string? entityId, AuditOutcome? outcome, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 100);
        if (page > 1000000) throw new ValidationAppException("Page is too large.");
        if (outcome.HasValue && !Enum.IsDefined(outcome.Value)) throw new ValidationAppException("Invalid outcome.");
        var q = db.AuditLogs.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(action)) q = q.Where(x => x.Action.Contains(action));
        if (!string.IsNullOrWhiteSpace(entityType)) q = q.Where(x => x.EntityType == entityType);
        if (!string.IsNullOrWhiteSpace(entityId)) q = q.Where(x => x.EntityId == entityId);
        if (outcome.HasValue) q = q.Where(x => x.Outcome == outcome);
        var count = await q.CountAsync(ct);
        var items = await q.OrderByDescending(x => x.OccurredAt).ThenByDescending(x => x.Id).Skip((page - 1) * pageSize).Take(pageSize)
         .Select(x => new AuditEntry(x.Id, x.ActorUserId, x.ActorEmail, x.Action, x.EntityType, x.EntityId, x.Outcome, x.IpAddress, x.Details, x.OccurredAt)).ToListAsync(ct);
        return new() { Items = items, Page = page, PageSize = pageSize, TotalCount = count };
    }
    public async Task<List<IncidentLink>> Links(int id, string kind, CancellationToken ct)
    {
        if (!await db.Incidents.AnyAsync(x => x.Id == id, ct)) throw new NotFoundException("Incident", id);
        return kind switch
        {
            "iocs" => await db.IncidentIocs.AsNoTracking().Where(x => x.IncidentId == id).OrderByDescending(x => x.AddedAt).Select(x => new IncidentLink(x.IocId, x.Ioc.Value, x.Ioc.Type.ToString(), (int)x.Role, x.Notes, x.AddedAt)).ToListAsync(ct),
            "assets" => await db.IncidentAssets.AsNoTracking().Where(x => x.IncidentId == id).OrderByDescending(x => x.AddedAt).Select(x => new IncidentLink(x.AssetId, x.Asset.Name, x.Asset.IpAddress, (int)x.ImpactType, x.Notes, x.AddedAt)).ToListAsync(ct),
            "mitre-techniques" => await db.IncidentMitreTechniques.AsNoTracking().Where(x => x.IncidentId == id).OrderByDescending(x => x.AddedAt).Select(x => new IncidentLink(x.MitreTechniqueId, x.MitreTechnique.Name, x.MitreTechnique.TechniqueId, null, x.Notes, x.AddedAt)).ToListAsync(ct),
            _ => throw new ValidationAppException("Unknown association.")
        };
    }
}
