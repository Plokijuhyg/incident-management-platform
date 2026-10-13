using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Api.Services;

// Runs AI-orchestrated assessment runs: the local LLM selects which bounded tools to run for a
// task, and the platform executes ONLY the reviewed allow-listed tools against the approved
// target (the gateway PRESET boundary still applies; exploitation tools are never exposed).
// One run is processed at a time so the single local model is not hammered concurrently.
public sealed class OrchestrationWorker(IServiceScopeFactory scopes,AssessmentGateway gateway,OrchestrationCancellation cancellation,IHostEnvironment environment,ILogger<OrchestrationWorker> logger):BackgroundService
{
 protected override async Task ExecuteAsync(CancellationToken ct)
 {
  if(environment.IsEnvironment("Testing")||!gateway.Enabled)return;
  await ResetOrphanedRuns(ct);
  while(!ct.IsCancellationRequested){try{await Tick(ct);}catch(OperationCanceledException)when(ct.IsCancellationRequested){break;}catch(Exception e){logger.LogError(e,"Orchestration worker paused; runs retained");}try{await Task.Delay(3000,ct);}catch(OperationCanceledException){break;}}
 }

 // A run left "Running" by a previous process has no live cancellation handle and will never be
 // picked up again (the worker only takes Pending), so fail it once on startup rather than orphan it.
 private async Task ResetOrphanedRuns(CancellationToken ct)
 {
  try
  {
   using var scope=scopes.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
   var stale=await db.OrchestrationRuns.Where(x=>x.Status=="Running").ToListAsync(ct);
   foreach(var r in stale){r.Status="Failed";r.FinishedAt=DateTime.UtcNow;r.Error="Interrupted by an API restart.";}
   if(stale.Count>0)await db.SaveChangesAsync(ct);
  }
  catch(Exception e){logger.LogError(e,"Could not reset orphaned orchestration runs");}
 }

 private async Task Tick(CancellationToken ct)
 {
  using var scope=scopes.CreateScope();
  var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
  var ollama=scope.ServiceProvider.GetRequiredService<OllamaAnalysis>();
  var run=await db.OrchestrationRuns.Where(x=>x.Status=="Pending").OrderBy(x=>x.CreatedAt).FirstOrDefaultAsync(ct);
  if(run is null)return;
  run.Status="Running";run.StartedAt=DateTime.UtcNow;run.Model=ollama.Model;await db.SaveChangesAsync(ct);
  var runCts=cancellation.Register(run.Id,ct);var runToken=runCts.Token;
  var transcript=new JsonArray();
  try
  {
   var target=gateway.ResolveTarget(run.TargetId,run.TargetIp);
   if(target is null||target.Ip!=run.TargetIp)throw new InvalidOperationException("Target is no longer approved.");
   var caps=await gateway.Send(HttpMethod.Get,"/v1/capabilities",null,runToken);
   if(!caps.TryGetProperty("connected",out var connected)||connected.ValueKind!=JsonValueKind.True)throw new InvalidOperationException("HexStrike gateway is not connected; no tools can be orchestrated.");
   var manifestId=caps.TryGetProperty("manifestId",out var mid)?mid.GetString():null;
   if(manifestId is null||!caps.TryGetProperty("tools",out var toolsEl)||toolsEl.ValueKind!=JsonValueKind.Array)throw new InvalidOperationException("Gateway capabilities are incomplete.");
   // Expose only AVAILABLE reviewed recon/scan tools (Network/Web). Exploitation is never available here.
   var toolSchemas=new JsonArray();var categories=new Dictionary<string,string>();
   foreach(var t in toolsEl.EnumerateArray())
   {
    if(!t.TryGetProperty("available",out var av)||av.ValueKind!=JsonValueKind.True)continue;
    var name=t.TryGetProperty("name",out var n)?n.GetString():null;if(name is null)continue;
    var category=t.TryGetProperty("category",out var cc)?cc.GetString():null;if(category is not("Network" or "Web"))continue;
    categories[name]=category;
    var function=new JsonObject{["name"]=name,["description"]=(t.TryGetProperty("description",out var d)?d.GetString():"")??""};
    function["parameters"]=t.TryGetProperty("inputSchema",out var schema)?JsonNode.Parse(schema.GetRawText()):new JsonObject{["type"]="object",["properties"]=new JsonObject()};
    toolSchemas.Add(new JsonObject{["type"]="function",["function"]=function});
   }
   if(toolSchemas.Count==0)throw new InvalidOperationException("No bounded recon/scan tools are available to orchestrate.");
   var system="You are an authorized security-assessment orchestrator in an isolated lab. You are given a task and ONE fixed, approved target. You SELECT which tools to run by calling them; the platform runs each selected tool against the approved target with safe, bounded parameters that you do not control. Only reconnaissance, scanning and vulnerability-detection tools are available - there is NO exploitation capability. Work step by step: call ONE tool, read its result, then decide the next step. Do not repeat a tool that already returned a result. When you have enough to answer the task, reply with a concise final summary (open services, likely vulnerabilities) and stop calling tools. Target: "+target.Ip+".";
   var messages=new JsonArray{new JsonObject{["role"]="system",["content"]=system},new JsonObject{["role"]="user",["content"]=run.Task}};
   for(var step=1;step<=run.MaxSteps;step++)
   {
    var (message,seconds)=await ollama.ChatWithTools(messages,toolSchemas,runToken);
    messages.Add(JsonNode.Parse(message.GetRawText()));
    var hasCalls=message.TryGetProperty("tool_calls",out var calls)&&calls.ValueKind==JsonValueKind.Array&&calls.GetArrayLength()>0;
    if(!hasCalls)
    {
     var final=message.TryGetProperty("content",out var content)?content.GetString():"";
     transcript.Add(new JsonObject{["step"]=step,["kind"]="final",["modelSeconds"]=seconds,["text"]=final});
     run.Summary=final;break;
    }
    foreach(var call in calls.EnumerateArray())
    {
     var fname=call.TryGetProperty("function",out var fn)&&fn.TryGetProperty("name",out var nm)?nm.GetString()??"":"";
     var fargs=call.TryGetProperty("function",out var fn2)&&fn2.TryGetProperty("arguments",out var ar)?ar.GetRawText():"{}";
     var node=new JsonObject{["step"]=step,["kind"]="tool",["modelSeconds"]=seconds,["tool"]=fname,["args"]=fargs};
     string output;
     if(!categories.TryGetValue(fname,out var category))
     {output="This tool is not permitted in the bounded orchestrator.";node["status"]="rejected";}
     else
     {
      var sw=Stopwatch.StartNew();
      try{output=await RunBoundedTool(category,fname,manifestId,target.Ip,run,runToken);node["status"]="ok";}
      catch(Exception e)when(e is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or KeyNotFoundException){output="Tool execution error: "+e.Message;node["status"]="error";}
      sw.Stop();node["toolSeconds"]=Math.Round(sw.Elapsed.TotalSeconds,1);
     }
     if(output.Length>2500)output=output[..2500];
     node["output"]=output;transcript.Add(node);
     messages.Add(new JsonObject{["role"]="tool",["content"]=output});
    }
    run.TranscriptJson=transcript.ToJsonString();await db.SaveChangesAsync(runToken);
   }
   run.Status="Completed";run.TranscriptJson=transcript.ToJsonString();run.FinishedAt=DateTime.UtcNow;
   db.AuditLogs.Add(new(){ActorUserId=run.RequestedById,Action="ORCHESTRATION_COMPLETED",EntityType="OrchestrationRun",EntityId=run.Id,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1",Outcome=AuditOutcome.Success});
   await db.SaveChangesAsync(ct);
  }
  catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
  catch(OperationCanceledException)when(runCts.IsCancellationRequested)
  {
   run.Status="Cancelled";run.FinishedAt=DateTime.UtcNow;run.Error="Stopped by the operator.";run.TranscriptJson=transcript.ToJsonString();
   db.AuditLogs.Add(new(){ActorUserId=run.RequestedById,Action="ORCHESTRATION_CANCELLED",EntityType="OrchestrationRun",EntityId=run.Id,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1",Outcome=AuditOutcome.Denied});
   await db.SaveChangesAsync(ct);
  }
  catch(Exception e)when(e is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or KeyNotFoundException)
  {
   run.Status="Failed";run.FinishedAt=DateTime.UtcNow;run.Error=e.Message.Length>1000?e.Message[..1000]:e.Message;run.TranscriptJson=transcript.ToJsonString();
   db.AuditLogs.Add(new(){ActorUserId=run.RequestedById,Action="ORCHESTRATION_FAILED",EntityType="OrchestrationRun",EntityId=run.Id,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1",Outcome=AuditOutcome.Failure});
   await db.SaveChangesAsync(ct);
  }
  finally{cancellation.Unregister(run.Id);}
 }

 // Execute one reviewed tool through the SAME bounded gateway path as a normal scan: resolve a
 // single-tool selection, submit a job (fresh id, so it is independent of the SecurityAssessment
 // queue and never auto-promotes), then poll until it finishes. Returns the raw job result text.
 private async Task<string> RunBoundedTool(string category,string name,string manifestId,string targetIp,OrchestrationRun run,CancellationToken ct)
 {
  var selection=await gateway.Send(HttpMethod.Post,"/v1/selection",new{categories=new[]{category},selectedTools=new[]{name},manifestId,confirmed=true,webPort=run.WebPort,webHttps=run.WebHttps,webPath=run.WebPath},ct);
  var jobId=Guid.NewGuid().ToString();
  await gateway.Send(HttpMethod.Post,"/v1/jobs",new{id=jobId,target=targetIp,profile="selected-tools",selection},ct);
  var deadline=DateTime.UtcNow.AddMinutes(20);
  while(DateTime.UtcNow<deadline)
  {
   await Task.Delay(4000,ct);
   var remote=await gateway.Send(HttpMethod.Get,"/v1/jobs/"+jobId,null,ct);
   if(remote.GetProperty("status").GetString() is "Completed" or "Partial" or "Failed")return remote.GetRawText();
  }
  return "Tool did not finish within the orchestrator time budget.";
 }
}
