using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
public record CreateAssessmentRequest(string TargetId,string Profile);
public record ScanAssessmentRequest(string TargetId,string[] Categories,string[]? SelectedTools,string ManifestId,bool Confirmed=false,int WebPort=80,bool WebHttps=false,string WebPath="/");
[ApiController,Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager}"),Route("api/assessments")]
public sealed class AssessmentsController(AssessmentService service,AssessmentGateway gateway,AppDbContext db):ControllerBase
{
 // Offline tool catalog: what the platform supports, visible before the Kali gateway is connected.
 [HttpGet("catalog")]public IActionResult Catalog()
 {
  var tools=HexStrikeCatalog.Tools();
  return Ok(new{
   enabled=gateway.Enabled,
   categories=HexStrikeCatalog.Categories,
   reviewedTotal=tools.Count(t=>t.Runnable),
   advertisedTotal=tools.Count(t=>!t.Runnable),
   total=tools.Count,
   note="Reviewed tools can run once the Kali gateway is connected and the binary is installed. Advertised tools are shown for planning only; the live gateway may advertise more tools still. Execution always requires an approved private lab target and intrusive-check confirmation.",
   tools
  });
 }
 [HttpGet("targets")]public IActionResult Targets()=>Ok(gateway.Targets.Where(x=>x.Approved).Select(x=>new{x.Id,x.Name,x.Ip}));
 [HttpGet("capabilities")]public async Task<IActionResult> Capabilities(CancellationToken ct)=>Ok(await gateway.Capabilities(ct));
 [HttpGet]public async Task<IActionResult> List(CancellationToken ct)=>Ok(await db.SecurityAssessments.AsNoTracking().OrderByDescending(x=>x.RequestedAt).Take(100).Select(x=>new{x.Id,x.TargetName,x.TargetIp,x.Profile,x.Status,x.RequestedAt,x.StartedAt,x.FinishedAt,x.Error}).ToListAsync(ct));
 [HttpGet("{id:guid}")]public async Task<IActionResult> Get(string id,CancellationToken ct)=>Ok(await service.Get(id,ct));
 [HttpPost]public IActionResult Create(CreateAssessmentRequest request)=>BadRequest(new{error="Select categories and tools through /api/assessments/scan.",traceId=HttpContext.TraceIdentifier});
 [HttpPost("scan")]
 public async Task<IActionResult> Scan(ScanAssessmentRequest request,CancellationToken ct)
 {
  var target=gateway.FindTarget(request.TargetId);
  if(target is null){await TelemetryAccess.Denied(db,HttpContext,request.TargetId,"UnapprovedTarget","ASSESSMENT_REJECTED","SecurityAssessment");return StatusCode(403,new{error="Assessment request rejected",traceId=HttpContext.TraceIdentifier});}
  if(request.Categories is null || request.Categories.Length is <1 or >4 || request.Categories.Any(c=>c is not ("Network" or "Web" or "Cloud" or "API")) || request.Categories.Distinct().Count()!=request.Categories.Length || request.SelectedTools?.Length>150 || request.WebPort is <1 or >65535)
   return BadRequest(new{error="Invalid scan selection",traceId=HttpContext.TraceIdentifier});
  try {
   var selection=await gateway.Send(HttpMethod.Post,"/v1/selection",new{categories=request.Categories,selectedTools=request.SelectedTools,manifestId=request.ManifestId,confirmed=request.Confirmed,webPort=request.WebPort,webHttps=request.WebHttps,webPath=request.WebPath},ct);
   var row=await service.CreateSelection(request.TargetId,selection.GetRawText(),ct);
   return AcceptedAtAction(nameof(Get),new{id=row.Id},row);
  } catch(HttpRequestException e) when(e.StatusCode==System.Net.HttpStatusCode.BadRequest) {
   await TelemetryAccess.Denied(db,HttpContext,request.TargetId,"InvalidOrUnconfirmedSelection","ASSESSMENT_REJECTED","SecurityAssessment");
   return BadRequest(new{error="Selection unavailable, changed, or requires confirmation. Refresh capabilities and review selection.",traceId=HttpContext.TraceIdentifier});
  }
 }
 [HttpPost("{id:guid}/cancel")]public async Task<IActionResult> Cancel(string id,CancellationToken ct){await service.Cancel(id,ct);return NoContent();}
}
