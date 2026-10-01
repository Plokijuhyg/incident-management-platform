using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
[ApiController,Route("api/{kind:regex(^(alerts|incidents)$)}/{id:int}/enrichment"),Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}")]
public sealed class EnrichmentController(AppDbContext db,IAlertService alerts,IIncidentService incidents,ICurrentUser user,VirusTotalClient client):ControllerBase
{
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web);
    private static List<IntelReport> Reports(string? value)=>value is null?[]:JsonSerializer.Deserialize<List<IntelReport>>(value,Json)??[];
    private async Task<(IntelIndicator[] candidates,string? metadata)> Load(string kind,int id,CancellationToken ct)
    {
        var candidates=new List<IntelIndicator>();string? metadata;
        if(kind=="alerts")
        {
            await alerts.GetByIdAsync(id,ct);var record=await db.Alerts.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
            metadata=record.EnrichmentJson;candidates.AddRange(IntelIndicators.FromPayload(record.RawPayload));
        }
        else
        {
            // Reuse existing incident read access; writes enforce the same assignment rule below.
            await incidents.GetByIdAsync(id,ct);metadata=await db.Incidents.Where(x=>x.Id==id).Select(x=>x.EnrichmentJson).SingleAsync(ct);
            var indicators=await db.IncidentIocs.Where(x=>x.IncidentId==id).Select(x=>new{x.Ioc.Type,x.Ioc.Value}).Take(100).ToListAsync(ct);
            foreach(var i in indicators)
            {
                var type=i.Type switch{IocType.IpAddress=>"ip",IocType.Domain=>"domain",IocType.Url=>"url",IocType.HashMd5 or IocType.HashSha1 or IocType.HashSha256=>"hash",_=>""};
                if(VirusTotalClient.Normalize(type,i.Value) is {} normalized)candidates.Add(normalized);
            }
            var payloads=await db.Alerts.Where(a=>a.IncidentId==id).OrderByDescending(a=>a.Id).Take(20).Select(a=>a.RawPayload).ToListAsync(ct);
            foreach(var payload in payloads)candidates.AddRange(IntelIndicators.FromPayload(payload));
        }
        return(candidates.Distinct().Take(50).ToArray(),metadata);
    }
    private void EnforceWrite(Incident incident)
    {
        if(!user.IsInRole(RoleNames.Admin) && !user.IsInRole(RoleNames.SecurityManager) && incident.AssignedToId!=user.Id)
            throw new IncidentPlatform.Api.Exceptions.ForbiddenException("You may only enrich incidents assigned to you.");
    }
    [HttpGet]
    public async Task<IActionResult> Get(string kind,int id,CancellationToken ct)
    {
        var state=await Load(kind,id,ct);return Ok(new{configured=client.Configured,candidates=state.candidates,reports=Reports(state.metadata)});
    }
    public sealed record LookupRequest(string Type,string Value,bool Confirmed);
    [HttpPost]
    public async Task<IActionResult> Enrich(string kind,int id,LookupRequest request,CancellationToken ct)
    {
        if(!request.Confirmed)return BadRequest(new{message="Confirm sharing this indicator with VirusTotal to retrieve its existing report."});
        var state=await Load(kind,id,ct);
        if(kind=="incidents")EnforceWrite(await db.Incidents.AsNoTracking().SingleAsync(x=>x.Id==id,ct));
        var indicator=VirusTotalClient.Normalize(request.Type??"",request.Value??"");
        if(indicator is null || !state.candidates.Contains(indicator))return BadRequest(new{message="Select a public indicator already present in this record. Private lab addresses are not submitted."});
        var previous=Reports(state.metadata).FirstOrDefault(r=>r.Type==indicator.Type && r.Value==indicator.Value && r.ExpiresAt>DateTime.UtcNow);
        var result=previous??await client.Lookup(indicator,ct);
        // The external request completes before opening a database transaction.
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        string Merge(string? json){var rows=Reports(json);rows.RemoveAll(x=>x.Type==result.Type&&x.Value==result.Value);rows.Add(result);return JsonSerializer.Serialize(rows.OrderByDescending(x=>x.CheckedAt).Take(50),Json);}
        if(kind=="alerts")
        {
            var record=await db.Alerts.FromSqlInterpolated($"SELECT * FROM Alerts WHERE Id={id} FOR UPDATE").SingleAsync(ct);await db.Entry(record).ReloadAsync(ct);record.EnrichmentJson=Merge(record.EnrichmentJson);
        }
        else
        {
            var record=await db.Incidents.FromSqlInterpolated($"SELECT * FROM Incidents WHERE Id={id} FOR UPDATE").SingleAsync(ct);await db.Entry(record).ReloadAsync(ct);EnforceWrite(record);record.EnrichmentJson=Merge(record.EnrichmentJson);record.Version++;
        }
        db.AuditLogs.Add(new(){Action="IOC_ENRICHMENT_REQUESTED",EntityType=kind=="alerts"?"Alert":"Incident",EntityId=id.ToString(),ActorUserId=user.Id,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Success,Details=JsonSerializer.Serialize(new{provider="VirusTotal",indicator.Type,result.Status,cached=previous is not null})});
        await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);return Ok(result);
    }
}
