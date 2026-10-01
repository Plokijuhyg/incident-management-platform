using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;

[ApiController,Route("api/automation"),Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager}")]
public sealed class AutomationController(AppDbContext db,ICurrentUser user,AutomationWorker worker,WindowsEventCollector collector) : ControllerBase
{
    [HttpGet("rules")]
    public async Task<IActionResult> Rules(CancellationToken ct)
    {
        var policies=await db.AutomationRules.AsNoTracking().Where(p=>!p.Id.StartsWith("SIGMA-")).OrderBy(x=>x.Id).ToListAsync(ct);
        var counts=await db.AutomationDecisions.GroupBy(x=>new{x.RuleId,x.Outcome}).Select(g=>new{g.Key.RuleId,g.Key.Outcome,count=g.Count()}).ToListAsync(ct);
        return Ok(new{catalogRevision=DetectionCatalog.Revision,worker.LastCycleAt,worker.Error,
            rules=policies.Select(p=>new{policy=p,definition=DetectionCatalog.Find(p.Id),counts=counts.Where(c=>c.RuleId==p.Id)}),
            owners=await db.Users.Where(u=>u.IsActive && u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin || r.Role.Name==RoleNames.SecurityManager || r.Role.Name==RoleNames.SocAnalyst))
                .OrderBy(u=>u.FullName).Select(u=>new{u.Id,u.FullName}).ToListAsync(ct)});
    }
    public sealed record UpdatePolicy(string Mode,int Version,int CorrelationMinutes,int? OwnerId);
    [HttpPut("rules/{id}"),Authorize(Roles=RoleNames.Admin)]
    public async Task<IActionResult> Update(string id,UpdatePolicy request,CancellationToken ct)
    {
        var definition=DetectionCatalog.Find(id);if(definition is null)return NotFound();
        if(request.Mode is not ("Disabled" or "Observe" or "AutoPromote") || request.CorrelationMinutes is < 5 or >1440)
            return BadRequest(new{message="Choose Disabled, Observe or AutoPromote and a 5-1440 minute correlation window."});
        if(request.Mode=="AutoPromote" && !definition.CanAutoPromote)return BadRequest(new{message="This rule requires human review and cannot auto-promote."});
        if(request.Mode=="AutoPromote" && request.OwnerId is null)return BadRequest(new{message="Select an active incident owner before enabling automatic promotion."});
        if(request.OwnerId.HasValue && !await db.Users.AnyAsync(u=>u.Id==request.OwnerId && u.IsActive &&
            u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin || r.Role.Name==RoleNames.SecurityManager || r.Role.Name==RoleNames.SocAnalyst),ct))return BadRequest(new{message="Owner must be an active SOC user."});
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var policy=await db.AutomationRules.FromSqlInterpolated($"SELECT * FROM AutomationRules WHERE Id={id} FOR UPDATE").SingleAsync(ct);
        if(policy.Version!=request.Version)return Conflict(new{message="Policy changed. Refresh and review before saving."});
        var before=new{policy.Mode,policy.Version,policy.CorrelationMinutes,policy.OwnerId};
        policy.Mode=request.Mode;policy.CorrelationMinutes=request.CorrelationMinutes;policy.OwnerId=request.OwnerId;
        policy.ApprovedById=user.Id;policy.Version++;policy.EffectiveFrom=DateTime.UtcNow;policy.UpdatedAt=policy.EffectiveFrom;
        db.AuditLogs.Add(new(){ActorUserId=user.Id,Action="AUTOMATION_POLICY_CHANGED",EntityType="AutomationRule",EntityId=id,
            Outcome=AuditOutcome.Success,OccurredAt=DateTime.UtcNow,Details=JsonSerializer.Serialize(new{before,after=policy,catalogRevision=DetectionCatalog.Revision})});
        await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);return Ok(policy);
    }
    [HttpGet("decisions")]
    public async Task<IActionResult> Decisions(long? before=null,CancellationToken ct=default)
    {
        var q=db.AutomationDecisions.AsNoTracking();if(before.HasValue)q=q.Where(x=>x.Id<before);
        var rows=await q.OrderByDescending(x=>x.Id).Take(51).ToListAsync(ct);
        return Ok(new{items=rows.Take(50),hasMore=rows.Count>50});
    }
    [HttpGet("coverage")]
    public async Task<IActionResult> Coverage(CancellationToken ct)
    {
        var checkpoints=await db.WindowsEventCheckpoints.AsNoTracking().Where(x=>x.Machine==Environment.MachineName && (x.Channel=="Security" || x.Channel=="Microsoft-Windows-Windows Defender/Operational"))
            .Select(x=>new{x.Channel,x.Enabled,x.LastCheckedAt,x.Error}).ToListAsync(ct);
        return Ok(new{observedAt=DateTime.UtcNow,scope="Local Windows API host; selected detection and triage capabilities only.",
            mappings=DetectionCatalog.Mappings,
            evidence=new{collector.Enabled,collector.RetentionDays,collector.LastCycleAt,collector.Error,channels=checkpoints,
                storedEvents=await db.WindowsEvents.CountAsync(ct),decisions=await db.AutomationDecisions.CountAsync(ct)},
            gaps=new[]{"CIS 8.10 requests at least 90 days of audit log retention. Current raw Windows retention must be evaluated against this requirement and storage capacity.",
                "Full ISO/IEC 27001 scope, risk treatment and Statement of Applicability have not been assessed.",
                "Four local detections do not provide full NIST or CIS coverage. No compliance percentage or certification is asserted."},
            benchmark=new{platform="Windows 11",profile="Level 1 proposed",status="Not assessed",version=(string?)null,
                reference="https://www.cisecurity.org/benchmark/microsoft_windows_desktop",
                reason="Select and pin the official benchmark edition/version applicable to Windows 11 Pro and collect configuration evidence. Event detections do not establish secure configuration compliance."}});
    }
}
