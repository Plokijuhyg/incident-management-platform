using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;
public sealed class AssessmentWorker(IServiceScopeFactory scopes,AssessmentGateway gateway,IHostEnvironment environment,ILogger<AssessmentWorker> logger):BackgroundService
{
 protected override async Task ExecuteAsync(CancellationToken ct)
 {
  if(environment.IsEnvironment("Testing")||!gateway.Enabled)return;
  while(!ct.IsCancellationRequested){try{await Sweep(ct);}catch(OperationCanceledException)when(ct.IsCancellationRequested){break;}catch(Exception e){logger.LogError(e,"Assessment worker paused; persisted jobs retained");}try{await Task.Delay(3000,ct);}catch(OperationCanceledException){break;}}
 }
 private async Task Sweep(CancellationToken ct)
 {
  using var scope=scopes.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
  var jobs=await db.SecurityAssessments.Where(x=>x.Status=="Pending"||x.Status=="Running").OrderBy(x=>x.RequestedAt).Take(10).ToListAsync(ct);
  foreach(var job in jobs)
  {
   try
   {
    if(job.Status=="Pending")
    {
     var target=gateway.Targets.SingleOrDefault(x=>x.Approved&&x.Id==job.TargetId&&x.Ip==job.TargetIp);
     if(target is null){job.Status="Failed";job.Error="Target approval changed before dispatch.";job.FinishedAt=DateTime.UtcNow;await db.SaveChangesAsync(ct);continue;}
     if(await db.SecurityAssessments.Where(x=>x.Id==job.Id&&x.Status=="Pending").ExecuteUpdateAsync(u=>u.SetProperty(x=>x.Status,"Running").SetProperty(x=>x.StartedAt,DateTime.UtcNow),ct)==0)continue;
     job.Status="Running";job.StartedAt=DateTime.UtcNow;db.Entry(job).State=EntityState.Unchanged;
    }
    // Idempotent gateway submission reconciles a lost acknowledgement or API restart.
    await gateway.Send(HttpMethod.Post,"/v1/jobs",job.RequestJson is null ? (object)new{id=job.Id,target=job.TargetIp,profile=job.Profile} : new{id=job.Id,target=job.TargetIp,profile=job.Profile,selection=JsonSerializer.Deserialize<JsonElement>(job.RequestJson)},ct);
    var remote=await gateway.Send(HttpMethod.Get,"/v1/jobs/"+job.Id,null,ct);
    var state=remote.GetProperty("status").GetString();
    if(state is "Completed" or "Partial" or "Failed")
    {
     job.RawResponse=remote.GetRawText();job.EvidenceSha256=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(job.RawResponse)));
     job.Status=state;job.FinishedAt=DateTime.UtcNow;job.Error=null;
     if(state is "Completed" or "Partial") {try{job.ObservationsJson=NormalizeResult(remote);if(state=="Partial")job.Error="Some checks failed. Inspect tool coverage and retained evidence.";}catch(Exception e)when(e is XmlException or InvalidOperationException){job.Status="Failed";job.Error="Tool output could not be parsed; original response retained.";}}
     else job.Error="Remote tool execution failed; inspect retained original evidence.";
     db.AuditLogs.Add(new(){ActorUserId=job.RequestedById,Action="ASSESSMENT_"+job.Status.ToUpperInvariant(),EntityType="SecurityAssessment",EntityId=job.Id,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1",Outcome=job.Status=="Completed"?AuditOutcome.Success:AuditOutcome.Failure});
    }
    else if(state is not ("Pending" or "Running")){job.Error="Unexpected remote status; execution outcome unconfirmed.";}
    else job.Error=null;
    await db.SaveChangesAsync(ct);
   }
   catch(HttpRequestException e)when(e.StatusCode==System.Net.HttpStatusCode.BadRequest)
   {
    job.Status="Failed";job.FinishedAt=DateTime.UtcNow;job.Error="Gateway rejected changed scope, policy, or selection before execution.";
    db.AuditLogs.Add(new(){ActorUserId=job.RequestedById,Action="ASSESSMENT_REJECTED",EntityType="SecurityAssessment",EntityId=job.Id,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Denied});
    await db.SaveChangesAsync(ct);
   }
   catch(Exception e)when(e is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException or KeyNotFoundException)
   {
    if(ct.IsCancellationRequested)throw;
    job.Error="Remote execution outcome unconfirmed. Reconciliation will retry the same job ID; no new scan is requested.";await db.SaveChangesAsync(ct);
   }
  }
 }
 public static string NormalizeResult(JsonElement remote)
 {
  var services=remote.TryGetProperty("xml",out var xml) ? JsonSerializer.Deserialize<List<JsonElement>>(Normalize(xml.GetString()??""))! : new List<JsonElement>();
  if(!remote.TryGetProperty("xml",out _) && !remote.TryGetProperty("steps",out _))throw new InvalidOperationException("Missing tool evidence");
  if(remote.TryGetProperty("findings",out var findings))
  {
   if(findings.ValueKind!=JsonValueKind.Array || findings.GetArrayLength()>2000)throw new InvalidOperationException("Invalid findings");
   foreach(var finding in findings.EnumerateArray())
   {
    if(finding.GetProperty("severity").GetString() is not ("Informational" or "Low" or "Medium" or "High" or "Critical") || finding.GetProperty("kind").GetString()!="Finding")throw new InvalidOperationException("Invalid finding classification");
    services.Add(finding.Clone());
   }
  }
  return JsonSerializer.Serialize(services);
 }
 public static string Normalize(string xml)
 {
  // Nmap emits this fixed, empty declaration. Remove only that exact line;
  // every other DTD remains prohibited, and original XML remains unchanged in evidence.
  xml=System.Text.RegularExpressions.Regex.Replace(xml,@"(?m)^[ \t]*<!DOCTYPE nmaprun>[ \t]*\r?$","");
  using var reader=XmlReader.Create(new StringReader(xml),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=4*1024*1024});
  var doc=XDocument.Load(reader);if(doc.Root?.Name!="nmaprun"||doc.Root.Element("runstats")?.Element("finished")?.Attribute("exit")?.Value!="success")throw new InvalidOperationException("Incomplete Nmap output.");
  return JsonSerializer.Serialize(doc.Descendants("port").Where(x=>x.Element("state")?.Attribute("state")?.Value=="open").Select(x=>new{port=(string?)x.Attribute("portid"),protocol=(string?)x.Attribute("protocol"),service=(string?)x.Element("service")?.Attribute("name"),product=(string?)x.Element("service")?.Attribute("product"),version=(string?)x.Element("service")?.Attribute("version"),severity="Informational",kind="Observed open service",evidence="Nmap XML port element"}));
 }
}
