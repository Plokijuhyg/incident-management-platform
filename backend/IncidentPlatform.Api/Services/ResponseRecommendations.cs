using System.Text.Json;
using IncidentPlatform.Api.Models;
namespace IncidentPlatform.Api.Services;
// Guidance only. This class has no executor, network client or mutation path.
public static class ResponseRecommendations
{
 public static string? For(Alert alert)
 {
  if(alert.Source!=AlertSource.WindowsEvent)return null;
  var tags=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  if(alert.SourceRuleId?.StartsWith("SIGMA-",StringComparison.Ordinal)==true && alert.RawPayload is {Length: <=2097152} raw)
   try {using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=32});if(doc.RootElement.ValueKind==JsonValueKind.Object && doc.RootElement.TryGetProperty("tags",out var values) && values.ValueKind==JsonValueKind.Array)foreach(var v in values.EnumerateArray().Take(100))if(v.ValueKind==JsonValueKind.String)tags.Add(v.GetString()!);}catch(JsonException){}
  bool Has(string id)=>tags.Any(t=>t.Equals("attack."+id,StringComparison.OrdinalIgnoreCase)||t.StartsWith("attack."+id+".",StringComparison.OrdinalIgnoreCase));
  if(Has("t1110"))return "Review authentication failures and confirm whether they share a source. Verify legitimate user activity; if abuse is confirmed, consider blocking that source at the lab boundary through an approved change.";
  if(alert.SourceRuleId=="WIN-AUDIT-CLEARED" || Has("t1070.001") || Has("t1685.005"))return "Preserve available evidence and review who cleared the logs. Check for approved maintenance and gaps in audit coverage before deciding on containment.";
  if(alert.SourceRuleId is "WIN-ACCOUNT-CREATED" or "WIN-LOCAL-GROUP-MEMBER" || Has("t1136") || Has("t1098"))return "Verify the account or group change with its owner and approved change record. Review granted privileges and consider reverting unauthorized access after human approval.";
  if(alert.SourceRuleId=="WIN-DEFENDER-DETECTION")return "Review Defender evidence and remediation status. Confirm the affected asset and consider isolation through the approved response process if the threat remains active.";
  if(Has("t1543"))return "Review the service configuration, executable and change owner. Preserve evidence and consider disabling an unauthorized service only after approval.";
  return null;
 }
}
