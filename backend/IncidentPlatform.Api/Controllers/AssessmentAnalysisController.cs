using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
public record AnalyzeRequest(string? Mode,string? Model=null);
[ApiController,Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.RedTeam}"),Route("api/assessments")]
public sealed class AssessmentAnalysisController(AppDbContext db,IConfiguration config,OllamaAnalysis ollama,IAuditContext audit):ControllerBase
{
 [HttpGet("analysis/status")]public IActionResult Status()=>Ok(new{configured=ollama.Configured,model=ollama.Model,promptVersion=OllamaAnalysis.DefensivePromptVersion,defensivePromptVersion=OllamaAnalysis.DefensivePromptVersion,offensivePromptVersion=OllamaAnalysis.OffensivePromptVersion});
 // Local models the operator can choose between (e.g. to compare the default 14B with a smaller model).
 [HttpGet("analysis/models")]public async Task<IActionResult> Models(CancellationToken ct)=>Ok(new{models=await ollama.InstalledModels(ct),defaultModel=ollama.Model});
 // A configured target may be revoked; a manual lab target stays approved only while its id still binds to the stored private IP.
 private bool Approved(SecurityAssessment row){var target=new ApprovedLabTargets(config).Find(row.TargetId);if(target is not null)return target.Ip==row.TargetIp;return row.TargetId=="manual:"+row.TargetIp&&AssessmentGateway.PrivateIp(row.TargetIp);}
 [HttpPost("{id:guid}/analysis")]
 public async Task<IActionResult> Analyze(string id,AnalyzeRequest? request,CancellationToken ct)
 {
  var mode=request?.Mode=="offensive"?"offensive":"defensive";
  var model=ollama.EffectiveModel(request?.Model);
  var row=await db.SecurityAssessments.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);if(row is null)return NotFound();
  if(!Approved(row)){await TelemetryAccess.Denied(db,HttpContext,row.TargetId,"UnapprovedTarget","ASSESSMENT_ANALYSIS_REJECTED","SecurityAssessment");return StatusCode(403,new{error="Assessment request rejected",traceId=HttpContext.TraceIdentifier});}
  if(row.Status is not("Completed" or "Partial")||string.IsNullOrWhiteSpace(row.EvidenceSha256))return Conflict(new{error="Analysis requires completed or partial scanner results with stored evidence."});
  AnalysisInput input;try{input=OllamaAnalysis.Prepare(row);}catch(Exception e)when(e is JsonException or InvalidOperationException){return Conflict(new{error="Normalized evidence is unavailable for analysis. Original scan output is retained."});}
  if(row.AnalysisJson is not null)try{var previous=JsonSerializer.Deserialize<AssessmentAnalysis>(row.AnalysisJson);if(previous is {Status:"Completed"} && previous.Model==model&&previous.EvidenceSha256==row.EvidenceSha256&&previous.InputSha256==input.Sha256&&previous.Mode==mode&&previous.PromptVersion==OllamaAnalysis.VersionFor(mode))return Ok(previous);}catch(JsonException){}
  db.AuditLogs.Add(audit.Create("ASSESSMENT_ANALYSIS_REQUESTED","SecurityAssessment",id,details:JsonSerializer.Serialize(new{model,mode,row.EvidenceSha256,input.Included,input.Total})));await db.SaveChangesAsync(ct);
  var result=await ollama.Analyze(row,input,ct,mode,request?.Model);
  if(!Approved(row)){await TelemetryAccess.Denied(db,HttpContext,row.TargetId,"ApprovalChanged","ASSESSMENT_ANALYSIS_REJECTED","SecurityAssessment");return StatusCode(403,new{error="Assessment request rejected",traceId=HttpContext.TraceIdentifier});}
  if(result.Status=="Busy")return StatusCode(409,new{error=result.Error});
  await using var transaction=await db.Database.BeginTransactionAsync(ct);
  var current=await db.SecurityAssessments.FromSqlInterpolated($"SELECT * FROM SecurityAssessments WHERE Id={id} FOR UPDATE").SingleOrDefaultAsync(ct);
  if(current is null||current.Status!=row.Status||current.TargetId!=row.TargetId||current.TargetIp!=row.TargetIp||current.EvidenceSha256!=row.EvidenceSha256||current.ObservationsJson!=row.ObservationsJson)return Conflict(new{error="Assessment evidence changed. Reload and retry analysis."});
  if(current.AnalysisJson!=row.AnalysisJson)return Conflict(new{error="Another analysis was saved. Reload to view it."});
  current.AnalysisJson=JsonSerializer.Serialize(result);
  db.AuditLogs.Add(audit.Create(result.Status=="Completed"?"ASSESSMENT_ANALYSIS_COMPLETED":"ASSESSMENT_ANALYSIS_FAILED","SecurityAssessment",id,result.Status=="Completed"?AuditOutcome.Success:AuditOutcome.Failure,JsonSerializer.Serialize(new{result.Status,result.Model,result.EvidenceSha256,result.InputSha256})));await db.SaveChangesAsync(ct);await transaction.CommitAsync(ct);return Ok(result);
 }
}
