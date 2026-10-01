namespace IncidentPlatform.Api.Models;
public sealed class SecurityAssessment
{
 public string Id {get;set;} = Guid.NewGuid().ToString();
 public int RequestedById {get;set;}
 public string TargetId {get;set;}="";
 public string TargetName {get;set;}="";
 public string TargetIp {get;set;}="";
 public string Profile {get;set;}="tcp-services";
 public string Status {get;set;}="Pending";
 public DateTime RequestedAt {get;set;}=DateTime.UtcNow;
 public DateTime? StartedAt {get;set;}
 public DateTime? FinishedAt {get;set;}
 public string? Error {get;set;}
 public string? RequestJson {get;set;}
 public string? RawResponse {get;set;}
 public string? EvidenceSha256 {get;set;}
 public string? AnalysisJson {get;set;}
 public string? ObservationsJson {get;set;}
}
