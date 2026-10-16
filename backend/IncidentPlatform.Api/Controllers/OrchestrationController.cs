using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;

public record CreateOrchestrationRequest(string Task,string? TargetId=null,string? TargetIp=null,int MaxSteps=6,int WebPort=80,bool WebHttps=false,string WebPath="/",string? Model=null);

// AI Orchestrator: a RED_TEAM/manager user submits a natural-language task; the local LLM selects
// which bounded, reviewed tools to run against the approved target (OrchestrationWorker executes
// them through the same PRESET-bounded gateway). No exploitation path is exposed here.
[ApiController,Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.RedTeam}"),Route("api/assessments/orchestrations")]
public sealed class OrchestrationController(AppDbContext db,AssessmentGateway gateway,OrchestrationCancellation cancellation,OllamaAnalysis ollama,ICurrentUser currentUser):ControllerBase
{
 [HttpGet]
 public async Task<IActionResult> List(CancellationToken ct)=>Ok(await db.OrchestrationRuns.AsNoTracking().OrderByDescending(x=>x.CreatedAt).Take(50)
  .Select(x=>new{x.Id,x.Task,x.TargetName,x.TargetIp,x.Status,x.Model,x.CreatedAt,x.StartedAt,x.FinishedAt,x.Error}).ToListAsync(ct));

 [HttpGet("{id:guid}")]
 public async Task<IActionResult> Get(string id,CancellationToken ct)
 {
  var run=await db.OrchestrationRuns.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
  return run is null?NotFound():Ok(Map(run));
 }

 [HttpPost]
 public async Task<IActionResult> Create(CreateOrchestrationRequest request,CancellationToken ct)
 {
  if(string.IsNullOrWhiteSpace(request.Task)||request.Task.Length>2000||request.WebPort is <1 or >65535||request.WebPath?.Length>200)
   return BadRequest(new{error="Provide a task (1-2000 chars) and a valid web scope.",traceId=HttpContext.TraceIdentifier});
  if(!gateway.Enabled)return StatusCode(503,new{error="HexStrike gateway is disabled until Laptop 2 is configured.",traceId=HttpContext.TraceIdentifier});
  var target=gateway.ResolveTarget(request.TargetId,request.TargetIp);
  if(target is null)
  {
   await TelemetryAccess.Denied(db,HttpContext,request.TargetId is{Length:>0}?request.TargetId:request.TargetIp??"","UnapprovedTarget","ORCHESTRATION_REJECTED","OrchestrationRun");
   return StatusCode(403,new{error="Choose an approved target or enter a private lab IP (10.x, 172.16-31.x, 192.168.x).",traceId=HttpContext.TraceIdentifier});
  }
  if(!string.IsNullOrWhiteSpace(request.Model)&&!(await ollama.InstalledModels(ct)).Contains(request.Model))
   return BadRequest(new{error="The selected model is not installed on the local Ollama server.",traceId=HttpContext.TraceIdentifier});
  var run=new OrchestrationRun{RequestedById=currentUser.Id,Task=request.Task.Trim(),TargetId=target.Id,TargetName=target.Name,TargetIp=target.Ip,
   MaxSteps=Math.Clamp(request.MaxSteps,1,10),WebPort=request.WebPort,WebHttps=request.WebHttps,WebPath=string.IsNullOrWhiteSpace(request.WebPath)?"/":request.WebPath,
   Model=ollama.EffectiveModel(request.Model)};
  db.OrchestrationRuns.Add(run);
  db.AuditLogs.Add(new(){ActorUserId=currentUser.Id,Action="ORCHESTRATION_REQUESTED",EntityType="OrchestrationRun",EntityId=run.Id,OccurredAt=DateTime.UtcNow,IpAddress=HttpContext.Connection.RemoteIpAddress?.ToString()??"",Outcome=AuditOutcome.Success});
  await db.SaveChangesAsync(ct);
  return AcceptedAtAction(nameof(Get),new{id=run.Id},Map(run));
 }

 // Stop a Pending or Running orchestration. A live run is cancelled via the in-process registry so
 // the current model call / tool poll aborts promptly; a Pending or orphaned run is marked directly.
 [HttpPost("{id:guid}/cancel")]
 public async Task<IActionResult> Cancel(string id,CancellationToken ct)
 {
  var run=await db.OrchestrationRuns.SingleOrDefaultAsync(x=>x.Id==id,ct);
  if(run is null)return NotFound();
  if(run.Status is "Completed" or "Failed" or "Cancelled")return NoContent();
  if(run.Status=="Pending"){run.Status="Cancelled";run.FinishedAt=DateTime.UtcNow;run.Error="Cancelled before it started.";}
  else if(!cancellation.TryCancel(id)){run.Status="Cancelled";run.FinishedAt=DateTime.UtcNow;run.Error="Stopped by the operator.";}
  db.AuditLogs.Add(new(){ActorUserId=currentUser.Id,Action="ORCHESTRATION_CANCELLED",EntityType="OrchestrationRun",EntityId=run.Id,OccurredAt=DateTime.UtcNow,IpAddress=HttpContext.Connection.RemoteIpAddress?.ToString()??"",Outcome=AuditOutcome.Denied});
  await db.SaveChangesAsync(ct);
  return NoContent();
 }

 private static object Map(OrchestrationRun r)=>new{r.Id,r.Task,r.TargetName,r.TargetIp,r.MaxSteps,r.Status,r.Model,r.Summary,r.Error,r.CreatedAt,r.StartedAt,r.FinishedAt,
  transcript=r.TranscriptJson is null?null:JsonSerializer.Deserialize<JsonElement?>(r.TranscriptJson)};
}
