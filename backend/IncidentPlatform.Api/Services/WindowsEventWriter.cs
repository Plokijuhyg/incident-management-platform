using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;
public static class WindowsEventWriter
{
    // Caller holds the collector database lock and a transaction. Both transports use this path.
    public static async Task<int> Store(AppDbContext db,IReadOnlyCollection<WindowsEvent> events,string peer,CancellationToken ct)
    {
        var keys=events.Select(e=>e.Fingerprint).ToArray();
        var known=await db.WindowsEvents.Where(e=>keys.Contains(e.Fingerprint)).Select(e=>e.Fingerprint).ToListAsync(ct);
        var imported=await db.DetectionRules.AsNoTracking().Where(r=>r.Enabled).ToListAsync(ct);
        var supported=imported.Where(r=>SigmaConditions.Unsupported(r) is null).ToArray();
        var added=0;
        foreach(var item in events.DistinctBy(e=>e.Fingerprint).Where(e=>!known.Contains(e.Fingerprint)))
        {
            var alerts=new List<Alert>();
            var builtin=WindowsEventRules.Evaluate(item);
            if(builtin is not null)alerts.Add(builtin);
            if(supported.Length>0)
            {
                try
                {
                    var fields=SigmaConditions.Fields(item);
                    foreach(var rule in supported)
                    {
                        try { if(SigmaConditions.Matches(rule,item,fields))alerts.Add(WindowsEventRules.CreateImported(rule,item)); }
                        catch(Exception ex) when(ex is System.Text.RegularExpressions.RegexMatchTimeoutException or ArgumentException or InvalidOperationException)
                        {
                            db.AuditLogs.Add(new(){Action="SIGMA_EVALUATION_FAILED",EntityType="DetectionRule",EntityId=rule.Id.ToString(),IpAddress=peer,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Denied,
                                Details=JsonSerializer.Serialize(new{rule.ExternalRuleId,eventFingerprint=item.Fingerprint,reason=ex.GetType().Name})});
                        }
                    }
                }
                catch(System.Xml.XmlException)
                {
                    db.AuditLogs.Add(new(){Action="SIGMA_EVENT_XML_INVALID",EntityType="WindowsEvent",EntityId=item.Fingerprint,IpAddress=peer,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Denied});
                }
            }
            foreach(var alert in alerts)
            {
                var previous=await db.Alerts.SingleOrDefaultAsync(a=>a.DeduplicationKey==alert.DeduplicationKey,ct);
                if(previous is null)
                {
                    db.Alerts.Add(alert);await db.SaveChangesAsync(ct);item.AlertId??=alert.Id;
                    db.AuditLogs.Add(new(){Action="WINDOWS_RULE_ALERT_CREATED",EntityType="Alert",EntityId=alert.Id.ToString(),IpAddress=peer,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Success,Details=JsonSerializer.Serialize(new{rule=alert.SourceRuleId,eventFingerprint=item.Fingerprint})});
                }
                else item.AlertId??=previous.Id;
            }
            db.WindowsEvents.Add(item);added++;
        }
        return added;
    }
    public sealed record ReevaluationResult(int Scanned,int Matched,int Created,int Duplicates,int Invalid,int[] AlertIds);
    // Explicit historical review only; the caller authenticates, validates stored IDs and holds the same collector lock.
    public static async Task<ReevaluationResult> Reevaluate(AppDbContext db,DetectionRule rule,IReadOnlyCollection<WindowsEvent> events,int actor,CancellationToken ct)
    {
        int matched=0,created=0,duplicates=0,invalid=0;var alertIds=new List<int>();
        foreach(var e in events)
        {
            ct.ThrowIfCancellationRequested();
            try{if(!SigmaConditions.Matches(rule,e,SigmaConditions.Fields(e)))continue;}
            catch(Exception ex) when(ex is System.Xml.XmlException or System.Text.RegularExpressions.RegexMatchTimeoutException or ArgumentException or InvalidOperationException)
            {
                invalid++;db.AuditLogs.Add(new(){Action="SIGMA_EVALUATION_FAILED",EntityType="DetectionRule",EntityId=rule.Id.ToString(),ActorUserId=actor,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Denied,Details=JsonSerializer.Serialize(new{eventId=e.Id,reason=ex.GetType().Name})});continue;
            }
            matched++;var key="sigma:"+rule.ExternalRuleId+":"+e.Fingerprint;
            var previous=await db.Alerts.SingleOrDefaultAsync(a=>a.DeduplicationKey==key,ct);
            if(previous is not null){duplicates++;alertIds.Add(previous.Id);continue;}
            var alert=WindowsEventRules.CreateImported(rule,e);
            // Detection occurred now; original event time and XML remain unchanged as evidence.
            alert.ReceivedAt=DateTime.UtcNow;
            alert.Description="Historical event re-evaluated after explicit administrator review. A rule match is not proof of compromise. "+alert.Description;
            var payload=System.Text.Json.Nodes.JsonNode.Parse(alert.RawPayload!)!.AsObject();
            payload["evaluationMode"]="HistoricalReview";payload["evaluatedAt"]=alert.ReceivedAt;payload["evaluatedBy"]=actor;payload["storedEventId"]=e.Id;payload["originalReceivedAt"]=e.ReceivedAt;
            alert.RawPayload=payload.ToJsonString();db.Alerts.Add(alert);await db.SaveChangesAsync(ct);e.AlertId??=alert.Id;alertIds.Add(alert.Id);created++;
        }
        db.AuditLogs.Add(new(){Action="SIGMA_HISTORY_EVALUATED",EntityType="DetectionRule",EntityId=rule.Id.ToString(),ActorUserId=actor,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Success,
            Details=JsonSerializer.Serialize(new{rule.ExternalRuleId,eventIds=events.Select(e=>e.Id),scanned=events.Count,matched,created,duplicates,invalid,alertIds})});
        return new(events.Count,matched,created,duplicates,invalid,alertIds.ToArray());
    }
}
