using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
namespace IncidentPlatform.Tests;
public class WindowsEventRulesTests
{
 [Theory]
 [InlineData("Application","Example",1102)]
 [InlineData("Security","Microsoft-Windows-Security-Auditing",4624)]
 [InlineData("Security","Microsoft-Windows-Security-Auditing",4625)]
 public void Ordinary_events_do_not_create_alerts(string channel,string provider,int id)
 { Assert.Null(WindowsEventRules.Evaluate(new(){Channel=channel,Provider=provider,EventId=id})); }
 [Fact]
 public void Audit_clear_rule_preserves_evidence_and_deduplicates()
 {
  var e=new WindowsEvent{Channel="Security",Provider="Microsoft-Windows-Eventlog",EventId=1102,RawXml="<Event />",Fingerprint=new string('A',64),ReceivedAt=DateTime.UtcNow,RecordId=42};
  var a=WindowsEventRules.Evaluate(e)!;Assert.Equal(AlertSource.WindowsEvent,a.Source);Assert.Equal("High",a.Severity);Assert.Equal("<Event />",System.Text.Json.JsonDocument.Parse(a.RawPayload!).RootElement.GetProperty("RawXml").GetString());Assert.Null(a.IncidentId);Assert.Equal(a.DeduplicationKey,WindowsEventRules.Evaluate(e)!.DeduplicationKey);
 }
}
