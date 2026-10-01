using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;

public sealed class AutomationProcessor(AppDbContext db)
{
    // A fresh scoped context per decision. Policy lock serializes correlation across workers.
    public async Task ProcessAsync(string ruleId, int alertId, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var policy = await db.AutomationRules.FromSqlInterpolated($"SELECT * FROM AutomationRules WHERE Id={ruleId} FOR UPDATE").SingleAsync(ct);
        if (policy.Mode == "Disabled") return;
        var alert = await db.Alerts.FromSqlInterpolated($"SELECT * FROM Alerts WHERE Id={alertId} FOR UPDATE").SingleOrDefaultAsync(ct);
        if (alert is null || alert.Status != AlertStatus.New || alert.Source != AlertSource.WindowsEvent ||
            alert.SourceRuleId != ruleId || alert.ReceivedAt < policy.EffectiveFrom ||
            await db.AutomationDecisions.AnyAsync(x=>x.AlertId==alertId,ct)) return;
        var now = DateTime.UtcNow;
        // Ineligible alerts still get a decision row. Without one the worker reselects them every
        // cycle, and 50 of them at the head of its queue would block every newer alert.
        async Task NotEligible(string reason, WindowsEvent? evidence=null) => await Record(new AutomationDecision {
            AlertId=alertId,RuleId=ruleId,PolicyVersion=policy.Version,Machine=evidence?.Machine ?? "",CreatedAt=now,
            Outcome="NotEligible",Reason=reason+" Alert remains available for human triage.",
            PolicySnapshot=JsonSerializer.Serialize(new { policy.Mode,policy.Version,catalogRevision=DetectionCatalog.Revision,eventId=evidence?.Id }) });
        var definition = DetectionCatalog.Find(ruleId);
        DetectionRule? imported=null;
        if(definition is null && ruleId.StartsWith("SIGMA-",StringComparison.Ordinal))
            imported=await db.DetectionRules.AsNoTracking().SingleOrDefaultAsync(r=>r.ExternalRuleId==ruleId.Substring(6) && r.Enabled,ct);
        if(definition is null && imported is null){await NotEligible("Detection rule is not in the catalog or is no longer enabled.");return;}
        if(imported is not null)
        {
            if(SigmaConditions.Unsupported(imported) is not null){await NotEligible("Imported rule uses unsupported Sigma conditions.");return;}
            definition=new DetectionDefinition(ruleId,imported.Title,"","",0,true,"Review the imported definition and evidence.","https://github.com/SigmaHQ/sigma",[]);
        }
        // Require a collector-owned row; API-submitted payloads cannot authorize automation.
        WindowsEvent? evidence;
        if(imported is null)
        {
            evidence=await db.WindowsEvents.AsNoTracking().FirstOrDefaultAsync(x=>x.AlertId==alertId,ct);
            if(evidence is null){await NotEligible("No collector-stored event backs this alert (missing, or removed by retention).");return;}
            if(evidence.Channel!=definition!.Channel || evidence.Provider!=definition.Provider || evidence.EventId!=definition.EventId){await NotEligible("Stored event does not match the rule's channel, provider and event ID.",evidence);return;}
        }
        else
        {
            string? fingerprint=null;
            try
            {
                if(alert.RawPayload is not null)
                {
                    using var payload=JsonDocument.Parse(alert.RawPayload);
                    if(payload.RootElement.ValueKind==JsonValueKind.Object && payload.RootElement.TryGetProperty("eventFingerprint",out var fp) && fp.ValueKind==JsonValueKind.String)
                        fingerprint=fp.GetString();
                }
            }
            catch(JsonException) { }
            if(fingerprint is null || alert.DeduplicationKey!="sigma:"+imported.ExternalRuleId+":"+fingerprint){await NotEligible("Alert payload does not identify its source event.");return;}
            evidence=await db.WindowsEvents.AsNoTracking().SingleOrDefaultAsync(e=>e.Fingerprint==fingerprint,ct);
            if(evidence is null){await NotEligible("No collector-stored event backs this alert (missing, or removed by retention).");return;}
            if(!SigmaConditions.Matches(imported,evidence,SigmaConditions.Fields(evidence))){await NotEligible("Stored event no longer matches the imported rule.",evidence);return;}
        }
        if(string.IsNullOrWhiteSpace(evidence.Machine)){await NotEligible("Stored event has no machine name.",evidence);return;}
        var decision = new AutomationDecision {
            AlertId=alert.Id,RuleId=ruleId,PolicyVersion=policy.Version,Machine=evidence.Machine,CreatedAt=now,
            Outcome="Observed",Reason="Observation only; alert remains available for human triage.",
            PolicySnapshot=JsonSerializer.Serialize(new { policy.Mode,policy.Version,policy.CorrelationMinutes,policy.OwnerId,
                policy.ApprovedById,policy.EffectiveFrom,catalogRevision=DetectionCatalog.Revision,definition!.Reference,definition.Mappings,
                eventId=evidence.Id,fingerprint=evidence.Fingerprint })
        };
        if(policy.Mode == "AutoPromote" && definition.CanAutoPromote)
        {
            var authorized = policy.ApprovedById.HasValue && await db.Users.AnyAsync(u=>u.Id==policy.ApprovedById && u.IsActive &&
                u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin),ct);
            var ownerActive=policy.OwnerId.HasValue && await db.Users.AnyAsync(u=>u.Id==policy.OwnerId && u.IsActive &&
                u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin || r.Role.Name==RoleNames.SecurityManager || r.Role.Name==RoleNames.SocAnalyst),ct);
            if(!authorized || !ownerActive) { decision.Outcome="NeedsReview"; decision.Reason="Policy approver or incident owner is inactive or no longer authorized. Manual triage required."; }
            else
            {
                var cutoff=now.AddMinutes(-policy.CorrelationMinutes);
                var previousId=await db.AutomationDecisions.Where(x=>x.RuleId==ruleId && x.PolicyVersion==policy.Version &&
                    x.Machine==evidence.Machine && x.IncidentId!=null && x.CreatedAt>=cutoff)
                    .OrderByDescending(x=>x.Id).Select(x=>x.IncidentId).FirstOrDefaultAsync(ct);
                Incident? incident=null;
                if(previousId.HasValue) incident=await db.Incidents.FromSqlInterpolated($"SELECT * FROM Incidents WHERE Id={previousId.Value} FOR UPDATE").SingleOrDefaultAsync(ct);
                if(incident is not null && (incident.CreatedAt<cutoff || incident.Status is IncidentStatus.Closed or IncidentStatus.Resolved or IncidentStatus.FalsePositive)) incident=null;
                var created=incident is null;
                if(created)
                {
                    incident=new Incident { EnrichmentJson=alert.EnrichmentJson,IncidentNumber=await IncidentNumberGenerator.GenerateNextAsync(db,ct),
                        Title=$"{definition.Name}: {evidence.Machine}",Description=$"Automatically opened for investigation by policy {ruleId} v{policy.Version}. Detection is not proof of compromise. Original evidence remains on alert #{alert.Id}.",
                        Severity=imported is null?IncidentSeverity.High:Enum.TryParse<IncidentSeverity>(imported.Severity,out var sigmaSeverity)?sigmaSeverity:IncidentSeverity.Low,
                        Priority=imported?.Severity is "Low" or "Informational"?IncidentPriority.Low:imported?.Severity=="Medium"?IncidentPriority.Medium:IncidentPriority.High,Category=ruleId=="WIN-DEFENDER-DETECTION"?IncidentCategory.Malware:IncidentCategory.Other,
                        Status=IncidentStatus.New,Source=IncidentSource.WindowsEvent,CreatedById=policy.ApprovedById!.Value,
                        AssignedToId=policy.OwnerId,DetectedAt=alert.DetectedAt,CreatedAt=now,UpdatedAt=now };
                    db.Incidents.Add(incident);await db.SaveChangesAsync(ct);
                }
                if(created && imported is not null)await SigmaIncidentReferences.CopyAsync(db,alert,incident!.Id,policy.ApprovedById!.Value,ct);
                var asset=await db.Assets.FirstOrDefaultAsync(a=>a.Hostname==evidence.Machine || a.Name==evidence.Machine,ct);
                if(asset is not null && !await db.IncidentAssets.AnyAsync(a=>a.IncidentId==incident!.Id && a.AssetId==asset.Id,ct))
                    db.IncidentAssets.Add(new(){IncidentId=incident!.Id,AssetId=asset.Id,ImpactType=ImpactType.Suspected,Notes="Asset named by matched event; compromise is not confirmed.",AddedById=policy.ApprovedById!.Value,AddedAt=now});
                alert.IncidentId=incident!.Id;alert.Status=AlertStatus.Promoted;alert.TriagedAt=now;
                // Null triage actor and system timeline distinguish automation from a human action.
                alert.TriagedById=null;
                incident.UpdatedAt=now;incident.Version++;
                decision.IncidentId=incident.Id;decision.Outcome=created?"IncidentCreated":"LinkedToIncident";
                decision.Reason=created?"Matched approved local incident criteria; opened for investigation.":"Same host and rule version within the configured incident window; linked to the open incident.";
                db.AuditLogs.Add(new(){Action=created?"AUTOMATION_INCIDENT_CREATED":"AUTOMATION_ALERT_LINKED",EntityType="Incident",EntityId=incident.Id.ToString(),
                    ActorEmail="system:incident-automation",Outcome=AuditOutcome.Success,OccurredAt=now,
                    Details=JsonSerializer.Serialize(new{ruleId,policy.Version,alertId=alert.Id,policy.ApprovedById,policy.OwnerId,decision.Reason})});
                db.IncidentTimelineEvents.Add(new(){IncidentId=incident.Id,EventType=TimelineEventType.AlertReceived,
                    Title=$"Automation linked alert #{alert.Id}",Description=$"{ruleId} v{policy.Version}: {decision.Reason}",
                    OccurredAt=alert.DetectedAt,RecordedAt=now,IsSystemGenerated=true});
            }
        }
        await Record(decision);

        async Task Record(AutomationDecision decision)
        {
            db.AutomationDecisions.Add(decision);
            db.AuditLogs.Add(new(){Action="AUTOMATION_DECISION",EntityType="Alert",EntityId=alertId.ToString(),
                ActorEmail="system:incident-automation",Outcome=AuditOutcome.Success,OccurredAt=now,
                Details=JsonSerializer.Serialize(new{ruleId,policy.Version,decision.Outcome,decision.IncidentId,decision.Reason})});
            await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);
        }
    }
}
public sealed class AutomationWorker(IServiceScopeFactory scopes,IHostEnvironment environment,ILogger<AutomationWorker> logger) : BackgroundService
{
    public DateTime? LastCycleAt {get;private set;}
    public string? Error {get;private set;}
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if(environment.IsEnvironment("Testing"))return;
        while(!ct.IsCancellationRequested)
        {
            try {
                using var scope=scopes.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var candidates=await (from a in db.Alerts.AsNoTracking()
                    join p in db.AutomationRules on a.SourceRuleId equals p.Id
                    where p.Mode!="Disabled" && a.Source==AlertSource.WindowsEvent && a.Status==AlertStatus.New && a.ReceivedAt>=p.EffectiveFrom &&
                        !db.AutomationDecisions.Any(d=>d.AlertId==a.Id)
                    select new{a.Id,RuleId=p.Id}).Distinct().OrderBy(x=>x.Id).Take(50).ToListAsync(ct);
                foreach(var candidate in candidates) {
                    using var work=scopes.CreateScope();
                    await work.ServiceProvider.GetRequiredService<AutomationProcessor>().ProcessAsync(candidate.RuleId,candidate.Id,ct);
                }
                LastCycleAt=DateTime.UtcNow;Error=null;
            } catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
            catch(Exception e){Error="Automation could not finish its cycle. Check server logs; uncommitted decisions will retry.";logger.LogError(e,"Automation cycle failed");}
            try{await Task.Delay(TimeSpan.FromSeconds(5),ct);}catch(OperationCanceledException){break;}
        }
    }
}
