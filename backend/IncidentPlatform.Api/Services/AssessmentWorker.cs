using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
     // Resolve the same way as creation/analysis: an approved configured target, or a typed private lab IP.
     var target=gateway.ResolveTarget(job.TargetId,job.TargetIp);
     if(target is null||target.Ip!=job.TargetIp){job.Status="Failed";job.Error="Target approval changed before dispatch.";job.FinishedAt=DateTime.UtcNow;await db.SaveChangesAsync(ct);continue;}
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
     // Auto-promote real findings into the SOC Alerts pipeline (PenTest source). Idempotent, so a retry
     // after a failed save never duplicates alerts; connectivity failures yield no findings, so none are raised.
     if(job.Status is "Completed" or "Partial" && job.ObservationsJson is not null)
     {
      var analysisText=await AnalyzeForAlertsAsync(scope.ServiceProvider,job,ct);
      await PromoteFindingsAsync(db,job,analysisText,ct);
     }
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
 // Runs the local-model defensive brief for a completed assessment, to use as the alert Description.
 // Never blocks promotion: if Ollama is unconfigured/unavailable the raw evidence still becomes alerts.
 private static async Task<string> AnalyzeForAlertsAsync(IServiceProvider sp,SecurityAssessment job,CancellationToken ct)
 {
  try
  {
   var ollama=sp.GetRequiredService<OllamaAnalysis>();
   var input=OllamaAnalysis.Prepare(job);
   var result=await ollama.Analyze(job,input,ct);
   job.AnalysisJson=JsonSerializer.Serialize(result);
   return result.Text??$"Local model analysis unavailable ({result.Status}). Review the raw tool evidence below.";
  }
  catch(Exception e) when(e is InvalidOperationException or JsonException or OperationCanceledException && !ct.IsCancellationRequested)
  {
   return "Local model analysis could not run on this evidence. Review the raw tool evidence below.";
  }
 }

 // Builds one PenTest alert per REAL finding (kind == "Finding"). Informational service inventory
 // (open ports) is excluded, and connectivity failures produce no findings, so neither is promoted.
 // RawPayload = the finding's verbatim tool evidence; Description = the model's analysis (separate field).
 public static List<Alert> BuildPenTestAlerts(SecurityAssessment job,string analysisText)
 {
  var alerts=new List<Alert>();
  if(job.ObservationsJson is null||job.Status is not("Completed" or "Partial"))return alerts;
  JsonDocument doc;
  try{doc=JsonDocument.Parse(job.ObservationsJson);}catch(JsonException){return alerts;}
  using(doc)
  {
   if(doc.RootElement.ValueKind!=JsonValueKind.Array)return alerts;
   foreach(var o in doc.RootElement.EnumerateArray())
   {
    if(o.ValueKind!=JsonValueKind.Object)continue;
    if(!o.TryGetProperty("kind",out var kind)||kind.GetString()!="Finding")continue; // real findings only
    string? Str(string name)=>o.TryGetProperty(name,out var v)&&v.ValueKind==JsonValueKind.String?v.GetString():null;
    var severity=Str("severity");
    if(severity is not("Informational" or "Low" or "Medium" or "High" or "Critical"))continue; // guard: no unclassified
    var tool=Str("tool")??"pentest";
    var endpoint=Str("endpoint")??Str("port");
    var cve=Str("cve");
    var title=Str("title")??cve??"Finding";
    var fingerprint=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{tool}|{cve}|{endpoint}|{title}|{severity}")))[..16];
    alerts.Add(new Alert
    {
     Title=Truncate($"PenTest: {title}"+(endpoint is null?"":$" @ {endpoint}"),200),
     Description=analysisText,            // model analysis only — never blended with raw output
     Source=AlertSource.PenTest,
     SourceRuleId=cve is not null?cve:"PENTEST-"+tool,
     DeduplicationKey=$"pentest:{job.Id}:{fingerprint}",
     Severity=severity,
     Status=AlertStatus.New,
     Host=job.TargetName,
     EntityIp=job.TargetIp,
     DetectedAt=job.FinishedAt??DateTime.UtcNow,
     ReceivedAt=DateTime.UtcNow,
     RawPayload=o.GetRawText(),           // verbatim finding evidence from HexStrike
    });
   }
  }
  return alerts;
 }

 // Adds the not-yet-promoted alerts for this assessment to the context (caller saves). Idempotent:
 // alerts whose DeduplicationKey already exists are skipped, so re-running after a retry adds nothing.
 public static async Task<int> PromoteFindingsAsync(AppDbContext db,SecurityAssessment job,string analysisText,CancellationToken ct)
 {
  var candidates=BuildPenTestAlerts(job,analysisText);
  if(candidates.Count==0)return 0;
  var keys=candidates.Select(a=>a.DeduplicationKey!).ToList();
  var existing=await db.Alerts.Where(a=>a.Source==AlertSource.PenTest&&keys.Contains(a.DeduplicationKey!)).Select(a=>a.DeduplicationKey!).ToListAsync(ct);
  var fresh=candidates.Where(a=>!existing.Contains(a.DeduplicationKey!)).ToList();
  if(fresh.Count==0)return 0;
  db.Alerts.AddRange(fresh);
  db.AuditLogs.Add(new(){ActorUserId=job.RequestedById,Action="ASSESSMENT_ALERTS_PROMOTED",EntityType="SecurityAssessment",EntityId=job.Id,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1",Outcome=AuditOutcome.Success,Details=JsonSerializer.Serialize(new{promoted=fresh.Count})});
  return fresh.Count;
 }

 private static string Truncate(string value,int max)=>value.Length<=max?value:value[..max];

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
