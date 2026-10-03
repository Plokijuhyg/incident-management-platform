using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
public record CreateAssessmentRequest(string TargetId,string Profile);
public record ScanAssessmentRequest(string TargetId,string[] Categories,string[]? SelectedTools,string ManifestId,bool Confirmed=false,int WebPort=80,bool WebHttps=false,string WebPath="/",string? TargetIp=null);
// Generic single-tool execution: name the HexStrike tool; the gateway builds and runs it.
public record ExecuteToolRequest(string ToolName,string? TargetId=null,string? TargetIp=null,bool Confirmed=false,int WebPort=80,bool WebHttps=false,string WebPath="/");
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
  var target=gateway.ResolveTarget(request.TargetId,request.TargetIp);
  if(target is null){await TelemetryAccess.Denied(db,HttpContext,request.TargetId is{Length:>0}?request.TargetId:request.TargetIp??"","UnapprovedTarget","ASSESSMENT_REJECTED","SecurityAssessment");return StatusCode(403,new{error="Assessment request rejected. Choose an approved target or enter a private lab IP (10.x, 172.16-31.x, 192.168.x).",traceId=HttpContext.TraceIdentifier});}
  if(request.Categories is null || request.Categories.Length is <1 or >4 || request.Categories.Any(c=>c is not ("Network" or "Web" or "Cloud" or "API")) || request.Categories.Distinct().Count()!=request.Categories.Length || request.SelectedTools?.Length>150 || request.WebPort is <1 or >65535)
   return BadRequest(new{error="Invalid scan selection",traceId=HttpContext.TraceIdentifier});
  try {
   var selection=await gateway.Send(HttpMethod.Post,"/v1/selection",new{categories=request.Categories,selectedTools=request.SelectedTools,manifestId=request.ManifestId,confirmed=request.Confirmed,webPort=request.WebPort,webHttps=request.WebHttps,webPath=request.WebPath},ct);
   var row=await service.CreateSelection(target,selection.GetRawText(),ct);
   return AcceptedAtAction(nameof(Get),new{id=row.Id},row);
  } catch(HttpRequestException e) when(e.StatusCode==System.Net.HttpStatusCode.BadRequest) {
   await TelemetryAccess.Denied(db,HttpContext,request.TargetId,"InvalidOrUnconfirmedSelection","ASSESSMENT_REJECTED","SecurityAssessment");
   return BadRequest(new{error="Selection unavailable, changed, or requires confirmation. Refresh capabilities and review selection.",traceId=HttpContext.TraceIdentifier});
  }
 }
 [HttpPost("{id:guid}/cancel")]public async Task<IActionResult> Cancel(string id,CancellationToken ct){await service.Cancel(id,ct);return NoContent();}

 // Generic execution path. The application validates identity, approved target, tool name and the
 // bounded web context, then delegates the actual tool execution to HexStrike via the gateway's
 // selection/job flow. The runnable set is DISCOVERED from the connected gateway, not hardcoded here;
 // the app never constructs a command, picks a binary, or runs a tool itself.
 [HttpPost("execute")]
 public async Task<IActionResult> Execute(ExecuteToolRequest request,CancellationToken ct)
 {
  var target=gateway.ResolveTarget(request.TargetId,request.TargetIp);
  if(target is null){await TelemetryAccess.Denied(db,HttpContext,request.TargetId is{Length:>0}?request.TargetId:request.TargetIp??"","UnapprovedTarget","ASSESSMENT_REJECTED","SecurityAssessment");return StatusCode(403,new{error="Assessment request rejected. Choose an approved target or enter a private lab IP.",traceId=HttpContext.TraceIdentifier});}
  if(string.IsNullOrEmpty(request.ToolName)||!Regex.IsMatch(request.ToolName,"^[a-z0-9_]{1,64}$")||request.WebPort is <1 or >65535)
   return BadRequest(new{error="Invalid tool name or scope",traceId=HttpContext.TraceIdentifier});
  // Discover tools from the connected gateway.
  JsonElement caps;
  try{caps=await gateway.Send(HttpMethod.Get,"/v1/capabilities",null,ct);}
  catch(Exception e)when(e is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException){return StatusCode(503,new{error="HexStrike gateway unavailable; tool discovery failed. No execution attempted.",traceId=HttpContext.TraceIdentifier});}
  if(!caps.TryGetProperty("connected",out var connected)||connected.ValueKind!=JsonValueKind.True||!caps.TryGetProperty("tools",out var tools)||tools.ValueKind!=JsonValueKind.Array)
   return StatusCode(503,new{error="HexStrike gateway is not connected; the live tool catalog is unavailable.",traceId=HttpContext.TraceIdentifier});
  var tool=tools.EnumerateArray().FirstOrDefault(t=>t.TryGetProperty("name",out var n)&&n.GetString()==request.ToolName);
  if(tool.ValueKind!=JsonValueKind.Object)
   return BadRequest(new{error=$"Tool '{request.ToolName}' was not discovered on the connected HexStrike server.",traceId=HttpContext.TraceIdentifier});
  if(!tool.TryGetProperty("available",out var available)||available.ValueKind!=JsonValueKind.True)
   return Conflict(new{error=$"Tool '{request.ToolName}' is not authorized to run (needs setup or blocked).",reason=tool.TryGetProperty("reason",out var r)?r.GetString():null,traceId=HttpContext.TraceIdentifier});
  var category=tool.TryGetProperty("category",out var cat)?cat.GetString():null;
  var manifestId=caps.TryGetProperty("manifestId",out var mid)?mid.GetString():null;
  if(category is not ("Network" or "Web" or "Cloud" or "API")||manifestId is null)
   return Conflict(new{error="Discovered tool metadata is incomplete; refresh capabilities and retry.",traceId=HttpContext.TraceIdentifier});
  try{
   var selection=await gateway.Send(HttpMethod.Post,"/v1/selection",new{categories=new[]{category},selectedTools=new[]{request.ToolName},manifestId,confirmed=request.Confirmed,webPort=request.WebPort,webHttps=request.WebHttps,webPath=request.WebPath},ct);
   var row=await service.CreateSelection(target,selection.GetRawText(),ct);
   return AcceptedAtAction(nameof(Get),new{id=row.Id},row);
  }catch(HttpRequestException e)when(e.StatusCode==System.Net.HttpStatusCode.BadRequest){
   await TelemetryAccess.Denied(db,HttpContext,request.TargetId is{Length:>0}?request.TargetId:request.TargetIp??"","InvalidOrUnconfirmedSelection","ASSESSMENT_REJECTED","SecurityAssessment");
   return BadRequest(new{error="Selection unavailable, changed, or requires confirmation. Refresh capabilities and retry.",traceId=HttpContext.TraceIdentifier});
  }
 }
}
