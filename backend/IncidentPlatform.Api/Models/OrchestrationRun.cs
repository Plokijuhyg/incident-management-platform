namespace IncidentPlatform.Api.Models;

// An AI-orchestrated assessment run: the local LLM reasons over a natural-language task and
// selects which bounded HexStrike tools to run; the platform executes only the reviewed
// allow-listed tools against the approved target. No exploitation tools are reachable here
// (the gateway PRESET boundary still applies). The full step-by-step transcript is stored.
public sealed class OrchestrationRun
{
 public string Id {get;set;} = Guid.NewGuid().ToString();
 public int RequestedById {get;set;}
 public string Task {get;set;}="";
 public string TargetId {get;set;}="";
 public string TargetName {get;set;}="";
 public string TargetIp {get;set;}="";
 public int MaxSteps {get;set;}=6;
 public int WebPort {get;set;}=80;
 public bool WebHttps {get;set;}
 public string WebPath {get;set;}="/";
 public string Status {get;set;}="Pending"; // Pending, Running, Completed, Failed
 public string Model {get;set;}="";
 public string? TranscriptJson {get;set;} // array of step objects (model decision, tool, result)
 public string? Summary {get;set;}         // the model's final free-text summary
 public string? Error {get;set;}
 public DateTime CreatedAt {get;set;}=DateTime.UtcNow;
 public DateTime? StartedAt {get;set;}
 public DateTime? FinishedAt {get;set;}
}
