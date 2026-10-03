using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services.Correlation;

/// <summary>
/// Groups related alerts into one case automatically. Unlike the admin-gated
/// AutoPromote policy (which promotes single Windows alerts), correlation is about
/// <b>patterns</b>: several alerts on the same entity (host, then user, then IP) inside
/// a time window, or a small cluster that includes a Critical. A single alert never
/// opens a case here — that stays the deliberate AutoPromote decision.
///
/// It only touches New, unlinked alerts that are not owned by an AutoPromote policy, so
/// it never competes with automation. Cases open at Tier 1 with a severity-based SLA and
/// a correlation key, so later alerts for the same entity join the open case.
/// </summary>
public sealed class CorrelationEngine(AppDbContext db)
{
    public const int WindowMinutes = 60;
    public const int Threshold = 3;

    public async Task<int> RunAsync(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var since = now.AddMinutes(-WindowMinutes);
        var candidates = await db.Alerts.AsNoTracking()
            .Where(a => a.Status == AlertStatus.New && a.IncidentId == null && a.ReceivedAt >= since
                && (a.Host != null || a.Username != null || a.EntityIp != null)
                && !db.AutomationRules.Any(p => p.Id == a.SourceRuleId && p.Mode == "AutoPromote"))
            .Select(a => new { a.Id, a.Host, a.Username, a.EntityIp, a.Severity })
            .ToListAsync(ct);
        if (candidates.Count == 0) return 0;

        var systemActorId = await db.Users
            .Where(u => u.IsActive && u.UserRoles.Any(r => r.Role.Name == RoleNames.Admin))
            .OrderBy(u => u.Id).Select(u => (int?)u.Id).FirstOrDefaultAsync(ct);
        if (systemActorId is null) return 0; // nobody to own the record

        var cases = 0;
        foreach (var group in candidates.GroupBy(a => Key(a.Host, a.Username, a.EntityIp)))
        {
            ct.ThrowIfCancellationRequested();
            var worst = group.Select(a => CaseSla.SeverityFrom(a.Severity)).Max();
            var count = group.Count();
            // A pattern: 3+ related alerts, or a 2+ cluster that includes a Critical.
            if (count < Threshold && !(count >= 2 && worst == IncidentSeverity.Critical)) continue;
            if (await CorrelateGroupAsync(group.Key, group.Select(a => a.Id).ToArray(), systemActorId.Value, now, ct)) cases++;
        }
        return cases;
    }

    // Host is the strongest entity, then user, then IP.
    private static string Key(string? host, string? user, string? ip) =>
        !string.IsNullOrEmpty(host) ? "host:" + host.ToUpperInvariant()
        : !string.IsNullOrEmpty(user) ? "user:" + user.ToLowerInvariant()
        : "ip:" + ip;

    private async Task<bool> CorrelateGroupAsync(string key, int[] alertIds, int actorId, DateTime now, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var idList = string.Join(",", alertIds); // ints from the DB — safe to inline
        var locked = await db.Alerts.FromSqlRaw($"SELECT * FROM Alerts WHERE Id IN ({idList}) FOR UPDATE").ToListAsync(ct);
        var eligible = locked.Where(a => a.Status == AlertStatus.New && a.IncidentId == null).ToList();
        if (eligible.Count == 0) return false;

        var worst = eligible.Select(a => CaseSla.SeverityFrom(a.Severity)).Max();
        var since = now.AddMinutes(-WindowMinutes);
        var incident = await db.Incidents
            .FromSqlInterpolated($"SELECT * FROM Incidents WHERE CorrelationKey={key} AND CreatedAt>={since} ORDER BY Id DESC LIMIT 1 FOR UPDATE")
            .SingleOrDefaultAsync(ct);
        if (incident is not null && incident.Status is IncidentStatus.Closed or IncidentStatus.Resolved or IncidentStatus.FalsePositive)
            incident = null;

        var created = incident is null;
        var entity = key.Contains(':') ? key[(key.IndexOf(':') + 1)..] : key;
        var entityKind = key.StartsWith("host:") ? "host" : key.StartsWith("user:") ? "user" : "source IP";
        if (created)
        {
            incident = new Incident
            {
                IncidentNumber = await IncidentNumberGenerator.GenerateNextAsync(db, ct),
                Title = $"Correlated activity on {entityKind} {entity}",
                Description = $"Opened automatically by correlation: {eligible.Count} related alert(s) on {entityKind} {entity} within {WindowMinutes} minutes. Correlation groups related signals; it is not proof of compromise. Review the linked alerts.",
                Severity = worst,
                Priority = CaseSla.PriorityFrom(worst),
                Status = IncidentStatus.New,
                Category = IncidentCategory.Other,
                Source = IncidentSource.Correlation,
                CreatedById = actorId,
                Tier = 1,
                CorrelationKey = key,
                DetectedAt = now,
                CreatedAt = now,
                UpdatedAt = now,
                SlaDueAt = CaseSla.DueAt(worst, now),
                Version = 0,
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);
            db.AuditLogs.Add(new() { Action = "CORRELATION_INCIDENT_CREATED", EntityType = "Incident", EntityId = incident.Id.ToString(), ActorEmail = "system:correlation", Outcome = AuditOutcome.Success, OccurredAt = now, Details = JsonSerializer.Serialize(new { key, alerts = eligible.Count, severity = worst.ToString() }) });
        }
        else if (worst > incident!.Severity)
        {
            // A worse alert joined the open case — raise its severity and tighten the SLA.
            incident.Severity = worst;
            incident.Priority = CaseSla.PriorityFrom(worst);
            incident.SlaDueAt = CaseSla.DueAt(worst, incident.CreatedAt);
        }

        foreach (var alert in eligible)
        {
            alert.IncidentId = incident!.Id;
            alert.Status = AlertStatus.Promoted;
            alert.TriagedAt = now;
            alert.TriagedById = null; // system
            db.IncidentTimelineEvents.Add(new()
            {
                IncidentId = incident.Id,
                EventType = TimelineEventType.AlertReceived,
                Title = $"Correlated alert #{alert.Id}: {alert.Title}",
                Description = $"Grouped by {entityKind} {entity}.",
                OccurredAt = alert.DetectedAt,
                RecordedAt = now,
                IsSystemGenerated = true,
            });
        }
        incident!.UpdatedAt = now;
        incident.Version++;
        db.AuditLogs.Add(new() { Action = created ? "CORRELATION_INCIDENT_CREATED" : "CORRELATION_ALERT_LINKED", EntityType = "Incident", EntityId = incident.Id.ToString(), ActorEmail = "system:correlation", Outcome = AuditOutcome.Success, OccurredAt = now, Details = JsonSerializer.Serialize(new { key, linked = eligible.Count, created }) });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return true;
    }
}

public sealed class CorrelationWorker(IServiceScopeFactory scopes, IHostEnvironment environment, ILogger<CorrelationWorker> logger) : BackgroundService
{
    public DateTime? LastCycleAt { get; private set; }
    public string? Error { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (environment.IsEnvironment("Testing")) return;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<CorrelationEngine>().RunAsync(ct);
                LastCycleAt = DateTime.UtcNow; Error = null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { Error = "Correlation cycle failed; alerts remain for manual triage."; logger.LogError(e, "Correlation cycle failed"); }
            try { await Task.Delay(TimeSpan.FromSeconds(10), ct); } catch (OperationCanceledException) { break; }
        }
    }
}
