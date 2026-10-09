using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Services;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;

[ApiController,Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}"),Route("api/soc")]
public sealed class SocController(AppDbContext db) : ControllerBase
{
    [HttpGet("overview")]
    public async Task<IActionResult> Overview(int hours=24,bool activeOnly=false,CancellationToken ct=default)
    {
        if(hours is <1 or >2160)return BadRequest();
        var now=DateTime.UtcNow;var start=now.AddHours(-hours);
        var incidents=db.Incidents.AsNoTracking().Where(x=>x.CreatedAt>=start && x.CreatedAt<=now);
        if(activeOnly)incidents=incidents.Where(x=>x.Status!=IncidentStatus.Closed && x.Status!=IncidentStatus.Resolved && x.Status!=IncidentStatus.FalsePositive);
        var selected=incidents.Select(x=>x.Id);
        return Ok(new{observedAt=now,hours,activeOnly,total=await incidents.CountAsync(ct),
            telemetry=new{events=await db.WindowsEvents.CountAsync(ct),alerts=await db.Alerts.CountAsync(ct),enabledRules=await db.DetectionRules.CountAsync(r=>r.Enabled,ct),assets=await db.Assets.CountAsync(ct)},
            categories=await incidents.GroupBy(x=>x.Category).Select(g=>new{label=g.Key.ToString(),count=g.Count(),high=g.Count(x=>x.Severity==IncidentSeverity.High || x.Severity==IncidentSeverity.Critical),medium=g.Count(x=>x.Severity==IncidentSeverity.Medium)}).ToListAsync(ct),
            topHosts=await db.IncidentAssets.Where(x=>selected.Contains(x.IncidentId)).GroupBy(x=>new{x.AssetId,x.Asset.Name,x.Asset.IpAddress})
                .OrderByDescending(g=>g.Count()).Take(10).Select(g=>new{id=g.Key.AssetId,name=g.Key.Name,ip=g.Key.IpAddress,count=g.Count(),high=g.Count(x=>x.Incident.Severity==IncidentSeverity.High || x.Incident.Severity==IncidentSeverity.Critical)}).ToListAsync(ct),
            topIncidents=await incidents.GroupBy(x=>x.Title).OrderByDescending(g=>g.Count()).Take(10).Select(g=>new{title=g.Key,count=g.Count()}).ToListAsync(ct),
            timeline=await incidents.GroupBy(x=>new{bucket=EF.Functions.DateDiffMinute(start,x.CreatedAt)/(hours<=24?5:60),x.Severity})
                .Select(g=>new{g.Key.bucket,severity=(int)g.Key.Severity,count=g.Count()}).ToListAsync(ct),
            start,bucketMinutes=hours<=24?5:60,
            latest=await incidents.OrderByDescending(x=>x.CreatedAt).Take(50).Select(x=>new{x.Id,x.IncidentNumber,x.Title,x.Severity,x.Status,x.Category,x.CreatedAt,owner=x.AssignedTo!=null?x.AssignedTo.FullName:null}).ToListAsync(ct)});
    }
    [HttpGet("attacks")]
    public async Task<IActionResult> Attacks(int hours=24,CancellationToken ct=default)
    {
        if(hours is <1 or >2160)return BadRequest();var start=DateTime.UtcNow.AddHours(-hours);
        var totalEvents=await db.WindowsEvents.CountAsync(e=>e.ReceivedAt>=start,ct);
        var sourceAlerts=await db.Alerts.Where(a=>a.Source==AlertSource.WindowsEvent && a.SourceRuleId!=null && a.SourceRuleId.StartsWith("SIGMA-") && a.ReceivedAt>=start).Select(a=>a.RawPayload).ToListAsync(ct);
        var tagged=new HashSet<string>();var references=new Dictionary<string,int>();
        foreach(var raw in sourceAlerts.Where(x=>x!=null))
        {
            using var doc=JsonDocument.Parse(raw!);var p=doc.RootElement;
            if(p.ValueKind!=JsonValueKind.Object || !p.TryGetProperty("tags",out var tags) || !p.TryGetProperty("eventFingerprint",out var fp))continue;
            var ids=tags.EnumerateArray().Where(t=>t.ValueKind==JsonValueKind.String).Select(t=>t.GetString()!).Where(t=>Regex.IsMatch(t,@"\Aattack\.t[0-9]{4}(\.[0-9]{3})?\z",RegexOptions.IgnoreCase)).Select(t=>t[7..].ToUpperInvariant()).Distinct().ToArray();
            if(ids.Length>0)tagged.Add(fp.GetString()!);
            foreach(var id in ids)references[id]=references.GetValueOrDefault(id)+1;
        }
        var classified=tagged.Count==0?0:await db.WindowsEvents.CountAsync(e=>e.ReceivedAt>=start && tagged.Contains(e.Fingerprint),ct);
        return Ok(new{hours,classification=new{totalEvents,taggedEvents=classified,unmappedEvents=totalEvents-classified},alertCounts=references.Select(x=>new{techniqueId=x.Key,count=x.Value}),
            techniques=await db.MitreTechniques.AsNoTracking().Where(x=>!x.IsDeprecated).OrderBy(x=>x.TechniqueId).Select(x=>new{x.Id,x.TechniqueId,x.Name,x.Tactic,x.IsSubTechnique,x.ParentTechniqueId,x.Url}).ToListAsync(ct),
            counts=await db.IncidentMitreTechniques.Where(x=>x.Incident.CreatedAt>=start).GroupBy(x=>x.MitreTechniqueId).Select(g=>new{id=g.Key,count=g.Count()}).ToListAsync(ct),
            devices=await (from a in db.IncidentAssets join t in db.IncidentMitreTechniques on a.IncidentId equals t.IncidentId where a.Incident.CreatedAt>=start
                group a by new{a.AssetId,a.Asset.Name,t.MitreTechnique.Tactic} into g select new{id=g.Key.AssetId,name=g.Key.Name,tactic=g.Key.Tactic,count=g.Select(x=>x.IncidentId).Distinct().Count()}).ToListAsync(ct)});
    }
    [HttpGet("techniques/{id:int}/incidents")]
    public async Task<IActionResult> TechniqueIncidents(int id,int hours=24,CancellationToken ct=default)
    {
        if(hours is <1 or >2160)return BadRequest();var start=DateTime.UtcNow.AddHours(-hours);
        return Ok(await db.IncidentMitreTechniques.Where(x=>x.MitreTechniqueId==id && x.Incident.CreatedAt>=start)
            .OrderByDescending(x=>x.Incident.CreatedAt).Take(100).Select(x=>new{x.Incident.Id,x.Incident.IncidentNumber,x.Incident.Title,x.Incident.Severity,x.Incident.Status}).ToListAsync(ct));
    }
    [HttpGet("tasks")]
    public async Task<IActionResult> Tasks(int? status=null,int page=1,CancellationToken ct=default)
    {
        page=Math.Clamp(page,1,100000);var q=db.ResponseActions.AsNoTracking();
        if(status.HasValue){if(status<0||status>4)return BadRequest();q=q.Where(x=>(int)x.Status==status);}
        return Ok(new{page,total=await q.CountAsync(ct),items=await q.OrderByDescending(x=>x.Id).Skip((page-1)*50).Take(50)
            .Select(x=>new{x.Id,x.IncidentId,x.Incident.IncidentNumber,x.ActionType,x.Description,x.TargetValue,x.Status,x.Result,x.PlannedAt,x.CompletedAt,owner=x.PerformedBy.FullName}).ToListAsync(ct)});
    }
    [HttpGet("analytics"),Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager}")]
    public async Task<IActionResult> Analytics(int minutes=60,string? search=null,string? channel=null,string? query=null,long? before=null,CancellationToken ct=default)
    {
        if(minutes is <5 or >10080 || search?.Length>200 || channel?.Length>255)return BadRequest();
        var now=DateTime.UtcNow;var start=now.AddMinutes(-minutes);var width=Math.Max(1,(int)Math.Ceiling(minutes/60.0));
        var q=db.WindowsEvents.AsNoTracking().Where(x=>x.ReceivedAt>=start && x.ReceivedAt<=now);
        if(!string.IsNullOrWhiteSpace(search))q=q.Where(x=>x.Message.Contains(search)||x.Provider.Contains(search)||x.Machine.Contains(search));
        if(!string.IsNullOrWhiteSpace(channel))q=q.Where(x=>x.Channel==channel);
        try { q=EventQuery.Apply(q,query); } catch(ArgumentException e) { return BadRequest(new{message=e.Message}); }
        var series=await q.GroupBy(x=>EF.Functions.DateDiffMinute(start,x.ReceivedAt)/width).Select(g=>new{index=g.Key,count=g.Count()}).ToListAsync(ct);
        var total=await q.CountAsync(ct);if(before.HasValue)q=q.Where(x=>x.Id<before);
        var rows=await q.OrderByDescending(x=>x.Id).Take(101).Select(x=>new{x.Id,x.ReceivedAt,x.Machine,x.Provider,x.Channel,x.EventId,x.Level,message=x.Message.Substring(0,Math.Min(x.Message.Length,500))}).ToListAsync(ct);
        return Ok(new{observedAt=now,start,width,total,series,items=rows.Take(100),hasMore=rows.Count>100});
    }
}
