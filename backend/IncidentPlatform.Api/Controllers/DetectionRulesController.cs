using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;

[ApiController, Route("api/detection-rules"), Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager}")]
public sealed class DetectionRulesController(AppDbContext db,ICurrentUser user) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(string? search=null,int page=1,CancellationToken ct=default)
    {
        if(page<1 || page>100000)return BadRequest(new{message="Invalid page."});
        var query=db.DetectionRules.AsNoTracking();
        if(!string.IsNullOrWhiteSpace(search))query=query.Where(r=>r.Title.Contains(search)||r.ExternalRuleId==search||r.ReferenceTag!=null&&r.ReferenceTag.Contains(search));
        var total=await query.CountAsync(ct);
        // Page small keys first: sorting large JSON rows can exhaust MySQL's sort buffer.
        var ids=await query.OrderBy(r=>r.Title).ThenBy(r=>r.Id).Skip((page-1)*25).Take(25).Select(r=>r.Id).ToListAsync(ct);
        var fetched=await db.DetectionRules.AsNoTracking().Where(r=>ids.Contains(r.Id)).ToListAsync(ct);
        var rows=ids.Select(id=>fetched.Single(r=>r.Id==id)).ToList();
        var policyIds=rows.Select(r=>"SIGMA-"+r.ExternalRuleId).ToArray();
        var policies=await db.AutomationRules.AsNoTracking().Where(p=>policyIds.Contains(p.Id)).ToListAsync(ct);
        var owners=await db.Users.Where(u=>u.IsActive && u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin || r.Role.Name==RoleNames.SecurityManager || r.Role.Name==RoleNames.SocAnalyst)).OrderBy(u=>u.FullName).Select(u=>new{u.Id,u.FullName}).ToListAsync(ct);
        return Ok(new{total,page,owners,items=rows.Select(r=>new{r.Id,r.ExternalRuleId,r.Title,r.Severity,r.ReferenceTag,r.Enabled,r.UpdatedAt,
            policy=policies.FirstOrDefault(p=>p.Id=="SIGMA-"+r.ExternalRuleId),unsupportedReason=SigmaConditions.Unsupported(r),definition=JsonSerializer.Deserialize<JsonElement>(r.DefinitionJson)})});
    }
    [HttpGet("{id:long}/preview")]
    public async Task<IActionResult> Preview(long id,int limit=1000,CancellationToken ct=default)
    {
        if(limit is <1 or >5000)return BadRequest(new{message="Preview limit must be 1-5000 events."});
        var rule=await db.DetectionRules.AsNoTracking().SingleOrDefaultAsync(r=>r.Id==id,ct);
        if(rule is null)return NotFound();
        var unsupported=SigmaConditions.Unsupported(rule);
        if(unsupported is not null)return BadRequest(new{message=unsupported});
        // Read only already-ingested records. Preview never creates alerts or incidents.
        var events=await db.WindowsEvents.AsNoTracking().OrderByDescending(e=>e.Id).Take(limit).ToListAsync(ct);
        var matches=new List<WindowsEvent>();int invalid=0;
        foreach(var e in events)
        {
            ct.ThrowIfCancellationRequested();
            try{if(SigmaConditions.Matches(rule,e,SigmaConditions.Fields(e)))matches.Add(e);}
            catch(Exception ex) when(ex is System.Xml.XmlException or System.Text.RegularExpressions.RegexMatchTimeoutException){invalid++;}
        }
        return Ok(new{scanned=events.Count,matched=matches.Count,invalid,scope="Latest stored events only; no records changed. Zero matches is not proof of absence.",samples=matches.Take(10).Select(e=>new{e.Id,e.EventId,e.Machine,e.Channel,e.TimeCreated})});
    }
    public sealed record ReevaluateRequest(long[] EventIds,DateTime UpdatedAt,bool Confirmed);
    [HttpPost("{id:long}/reevaluate"),Authorize(Roles=RoleNames.Admin)]
    public async Task<IActionResult> Reevaluate(long id,ReevaluateRequest request,CancellationToken ct)
    {
        if(!request.Confirmed)return BadRequest(new{message="Confirm evaluation of the selected stored events. Matching rules can create alerts and incidents under the reviewed policy."});
        if(request.EventIds is null || request.EventIds.Length is <1 or >100 || request.EventIds.Any(x=>x<=0))return BadRequest(new{message="Select 1-100 existing event IDs."});
        await db.Database.OpenConnectionAsync(ct);
        var connection=(MySqlConnector.MySqlConnection)db.Database.GetDbConnection();
        var lockName="win-events:"+Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(connection.Database)))[..40];
        await using var guard=new MySqlConnector.MySqlCommand("SELECT GET_LOCK(@name,5)",connection);guard.Parameters.AddWithValue("@name",lockName);
        if(Convert.ToInt32(await guard.ExecuteScalarAsync(ct))!=1)return StatusCode(503,new{message="Collector is busy; retry the same selection."});
        try
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            var rule=await db.DetectionRules.FromSqlInterpolated($"SELECT * FROM DetectionRules WHERE Id={id} FOR UPDATE").SingleOrDefaultAsync(ct);
            if(rule is null)return NotFound();
            if(!rule.Enabled)return BadRequest(new{message="Review and enable this rule first."});
            if(rule.UpdatedAt!=request.UpdatedAt)return Conflict(new{message="Definition changed. Refresh and review again."});
            var unsupported=SigmaConditions.Unsupported(rule);if(unsupported is not null)return BadRequest(new{message=unsupported});
            var ids=request.EventIds.Distinct().ToArray();
            var events=await db.WindowsEvents.Where(e=>ids.Contains(e.Id)).OrderBy(e=>e.Id).ToListAsync(ct);
            if(events.Count!=ids.Length)return BadRequest(new{message="Every selected event must already exist in the validated event store."});
            var result=await WindowsEventWriter.Reevaluate(db,rule,events,user.Id,ct);
            await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);
            return Ok(result);
        }
        finally
        {
            await using var release=new MySqlConnector.MySqlCommand("SELECT RELEASE_LOCK(@name)",connection);release.Parameters.AddWithValue("@name",lockName);
            await release.ExecuteScalarAsync(CancellationToken.None);
        }
    }
    public sealed record Review(bool Enabled,DateTime UpdatedAt,bool Confirmed,string Mode="Observe",int? OwnerId=null,int CorrelationMinutes=60);
    [HttpPut("{id:long}/enabled"),Authorize(Roles=RoleNames.Admin)]
    public async Task<IActionResult> SetEnabled(long id,Review request,CancellationToken ct)
    {
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var rule=await db.DetectionRules.FromSqlInterpolated($"SELECT * FROM DetectionRules WHERE Id={id} FOR UPDATE").SingleOrDefaultAsync(ct);
        if(rule is null)return NotFound();
        if(rule.UpdatedAt!=request.UpdatedAt)return Conflict(new{message="Definition changed. Refresh and review again."});
        if(request.Enabled && !request.Confirmed)return BadRequest(new{message="Review the source fields and conditions and confirm before enabling."});
        var unsupported=SigmaConditions.Unsupported(rule);
        if(request.Enabled && unsupported is not null)return BadRequest(new{message=unsupported});
        if(request.Mode is not ("Observe" or "AutoPromote") || request.CorrelationMinutes is <5 or >1440)return BadRequest(new{message="Choose Observe or AutoPromote and a 5-1440 minute window."});
        if(request.Enabled && request.Mode=="AutoPromote" && (request.OwnerId is null || !await db.Users.AnyAsync(u=>u.Id==request.OwnerId && u.IsActive && u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin || r.Role.Name==RoleNames.SecurityManager || r.Role.Name==RoleNames.SocAnalyst),ct)))
            return BadRequest(new{message="Choose an active incident owner before automatic promotion."});
        var policyId="SIGMA-"+rule.ExternalRuleId;
        var policy=await db.AutomationRules.SingleOrDefaultAsync(p=>p.Id==policyId,ct);
        if(policy is null){policy=new AutomationRule{Id=policyId};db.AutomationRules.Add(policy);}
        policy.Mode=request.Enabled?request.Mode:"Disabled";policy.OwnerId=request.OwnerId;policy.ApprovedById=user.Id;
        policy.CorrelationMinutes=request.CorrelationMinutes;policy.Version++;policy.EffectiveFrom=DateTime.UtcNow;policy.UpdatedAt=policy.EffectiveFrom;
        var now=DateTime.UtcNow;
        rule.Enabled=request.Enabled;rule.UpdatedAt=new DateTime(now.Ticks-now.Ticks%10,DateTimeKind.Utc);
        db.AuditLogs.Add(new(){ActorUserId=user.Id,Action="DETECTION_RULE_REVIEWED",EntityType="DetectionRule",EntityId=id.ToString(),Outcome=AuditOutcome.Success,OccurredAt=DateTime.UtcNow,
            Details=JsonSerializer.Serialize(new{rule.ExternalRuleId,rule.Enabled,rule.UpdatedAt,policy.Mode,policy.OwnerId,policy.Version})});
        await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);
        return Ok(new{rule.Id,rule.Enabled,rule.UpdatedAt});
    }
}
