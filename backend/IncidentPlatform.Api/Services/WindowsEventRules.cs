using IncidentPlatform.Api.Models;
using System.Text.Json;
namespace IncidentPlatform.Api.Services;
// Deterministic review signals, not a claim that the host is compromised.
public static class WindowsEventRules
{
    public static Alert? Evaluate(WindowsEvent e)
    {
        var rule = (e.Channel, e.Provider, e.EventId) switch
        {
            ("Security", "Microsoft-Windows-Eventlog", 1102) => ("WIN-AUDIT-CLEARED", "High", "Windows Security audit log cleared"),
            ("Security", "Microsoft-Windows-Security-Auditing", 4720) => ("WIN-ACCOUNT-CREATED", "Medium", "Windows user account created"),
            ("Security", "Microsoft-Windows-Security-Auditing", 4732) => ("WIN-LOCAL-GROUP-MEMBER", "Medium", "Member added to a local security group"),
            ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", 1116) => ("WIN-DEFENDER-DETECTION", "High", "Microsoft Defender reported a threat"),
            _ => ((string Id, string Severity, string Title)?)null
        };
        if (rule is not { } r) return null;
        return new Alert { Title=r.Title, Description="Observed Windows event. Rule severity is a review priority, not proof of compromise. Review the original XML and context before promoting to an incident.",
            Source=AlertSource.WindowsEvent, SourceRuleId=r.Id, ExternalId=e.RecordId?.ToString(), DeduplicationKey="windows:"+e.Fingerprint,
            Severity=r.Severity, Status=AlertStatus.New, DetectedAt=e.TimeCreated??e.ReceivedAt, ReceivedAt=e.ReceivedAt,
            RawPayload=JsonSerializer.Serialize(new { e.Machine,e.Channel,e.Provider,e.EventId,e.RecordId,e.TimeCreated,e.RawXml,rule=r.Id }) };
    }
    public static Alert CreateImported(DetectionRule rule, WindowsEvent e)
    {
        var definition=JsonSerializer.Deserialize<JsonElement>(rule.DefinitionJson);
        return new Alert {
            Title=rule.Title.Length>200?rule.Title[..200]:rule.Title,
            Description="Imported Sigma detection matched validated Windows event evidence. Review the original event and false-positive context before incident promotion.",
            Source=AlertSource.WindowsEvent,SourceRuleId="SIGMA-"+rule.ExternalRuleId,
            ExternalId=e.RecordId?.ToString(),DeduplicationKey="sigma:"+rule.ExternalRuleId+":"+e.Fingerprint,
            Severity=rule.Severity,Status=AlertStatus.New,DetectedAt=e.TimeCreated??e.ReceivedAt,ReceivedAt=e.ReceivedAt,
            RawPayload=JsonSerializer.Serialize(new { e.Machine,e.Channel,e.Provider,e.EventId,e.RecordId,e.TimeCreated,e.RawXml,
                eventFingerprint=e.Fingerprint,rule="SIGMA-"+rule.ExternalRuleId,ruleTitle=rule.Title,ruleUpdatedAt=rule.UpdatedAt,
                tags=definition.GetProperty("tags"),sourceSha256=definition.GetProperty("sourceSha256") })
        };
    }
}
