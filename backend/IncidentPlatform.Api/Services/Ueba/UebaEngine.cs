using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services.Ueba;

/// <summary>
/// User/entity behavior analytics over ingested logs. Deliberately simple and
/// explainable: per-user rolling baselines (failed-login counts, seen source IPs)
/// and two anomalies — a failed-login spike and a login from a never-before-seen
/// source. Anomalies become <see cref="AlertSource.Ueba"/> alerts carrying the entity,
/// so they flow into correlation like any other alert. Not a black-box model, and a
/// flag is a lead to investigate, never proof of compromise.
/// </summary>
public sealed class UebaEngine(AppDbContext db)
{
    public const int FailedLoginThreshold = 5;
    public const int LearningEvents = 10;
    private const int MaxIpSet = 50;

    /// <summary>Folds new log events into baselines and raises anomaly alerts. Returns the new cursor.</summary>
    public async Task<long> ProcessAsync(long fromEventId, int maxBatch, CancellationToken ct)
    {
        var events = await db.LogEvents.AsNoTracking()
            .Where(e => e.Id > fromEventId && e.User != null)
            .OrderBy(e => e.Id).Take(maxBatch).ToListAsync(ct);
        if (events.Count == 0) return fromEventId;

        var users = events.Select(e => e.User!).Distinct().ToList();
        var byUser = (await db.EntityProfiles.Where(p => p.EntityType == "user" && users.Contains(p.EntityValue)).ToListAsync(ct))
            .ToDictionary(p => p.EntityValue, StringComparer.OrdinalIgnoreCase);
        var raised = new HashSet<string>(StringComparer.Ordinal);
        var existingKeys = await db.Alerts
            .Where(a => a.Source == AlertSource.Ueba && a.DeduplicationKey != null && a.ReceivedAt >= DateTime.UtcNow.AddHours(-24))
            .Select(a => a.DeduplicationKey!).ToListAsync(ct);
        raised.UnionWith(existingKeys);

        foreach (var e in events)
        {
            var user = e.User!;
            if (!byUser.TryGetValue(user, out var p))
            {
                p = new EntityProfile { EntityType = "user", EntityValue = user.Length > 255 ? user[..255] : user, FirstSeenAt = e.EventTime, WindowStart = e.EventTime, KnownSourceIpsJson = "[]", UpdatedAt = e.ReceivedAt };
                db.EntityProfiles.Add(p);
                byUser[user] = p;
            }
            p.LastSeenAt = e.EventTime;
            p.EventCount++;
            p.LastEventId = e.Id;
            if (e.EventTime >= p.WindowStart.AddHours(1)) { p.WindowStart = e.EventTime; p.FailedLoginsHour = 0; }

            var isLogin = IsLogin(e.Action);
            var ips = Ips(p.KnownSourceIpsJson);
            var newIp = !string.IsNullOrEmpty(e.SourceIp) && !ips.Contains(e.SourceIp);

            if (isLogin && e.Outcome == "failure")
            {
                p.FailedLoginsHour++;
                if (p.FailedLoginsHour >= FailedLoginThreshold)
                    Raise(p, "Failed-login spike", $"{p.FailedLoginsHour} failed logins within the hour for {user}.",
                        "High", "ueba:failspike:" + user.ToLowerInvariant() + ":" + p.WindowStart.Ticks, e, 60, raised);
            }
            if (isLogin && e.Outcome == "success" && newIp && p.EventCount >= LearningEvents)
                Raise(p, "Login from new source", $"First successful login for {user} from {e.SourceIp}.",
                    "Medium", "ueba:newip:" + user.ToLowerInvariant() + ":" + e.SourceIp, e, 40, raised);

            if (newIp)
            {
                ips.Add(e.SourceIp!);
                if (ips.Count > MaxIpSet) ips = ips.Skip(ips.Count - MaxIpSet).ToList();
                p.KnownSourceIpsJson = JsonSerializer.Serialize(ips);
            }
            p.UpdatedAt = e.ReceivedAt;
        }

        await db.SaveChangesAsync(ct);
        return events[^1].Id;
    }

    private void Raise(EntityProfile p, string title, string description, string severity, string dedupKey, LogEvent e, int riskDelta, HashSet<string> raised)
    {
        p.RiskScore = Math.Min(100, p.RiskScore + riskDelta);
        p.LastAnomaly = title;
        p.LastAnomalyAt = DateTime.UtcNow;
        if (!raised.Add(dedupKey)) return; // already alerted (this batch or the last 24h)

        db.Alerts.Add(new Alert
        {
            Title = $"UEBA: {title} — {p.EntityValue}",
            Description = description + " Behavioral anomaly, not proof of compromise.",
            Source = AlertSource.Ueba,
            SourceRuleId = title.Contains("spike", StringComparison.OrdinalIgnoreCase) ? "UEBA-FAILED-LOGIN-SPIKE" : "UEBA-NEW-SOURCE",
            DeduplicationKey = dedupKey,
            Severity = severity,
            Status = AlertStatus.New,
            Username = p.EntityValue,
            EntityIp = e.SourceIp,
            Host = e.Host,
            DetectedAt = e.EventTime,
            ReceivedAt = DateTime.UtcNow,
            RawPayload = JsonSerializer.Serialize(new { entity = p.EntityValue, anomaly = title, e.SourceIp, e.Host, failedLoginsHour = p.FailedLoginsHour, logFingerprint = e.Fingerprint }),
        });
        db.AuditLogs.Add(new AuditLog { Action = "UEBA_ANOMALY_ALERT", EntityType = "EntityProfile", EntityId = p.EntityValue, ActorEmail = "system:ueba", Outcome = AuditOutcome.Success, OccurredAt = DateTime.UtcNow, IpAddress = "127.0.0.1", Details = JsonSerializer.Serialize(new { entity = p.EntityValue, anomaly = title, dedupKey }) });
    }

    private static bool IsLogin(string? action) =>
        action is not null && (action.Contains("login") || action.Contains("logon") || action.Contains("auth") || action.Contains("connect") || action.Contains("signin"));

    private static List<string> Ips(string json)
    {
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch (JsonException) { return []; }
    }
}

public sealed class UebaWorker(IServiceScopeFactory scopes, IHostEnvironment environment, ILogger<UebaWorker> logger) : BackgroundService
{
    public DateTime? LastCycleAt { get; private set; }
    public string? Error { get; private set; }
    private long _cursor;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (environment.IsEnvironment("Testing")) return;
        // Forward-looking: start from the current tail, don't backfill history on boot.
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            _cursor = await db.LogEvents.MaxAsync(e => (long?)e.Id, ct) ?? 0;
        }
        catch (Exception e) { logger.LogWarning(e, "UEBA could not read its start cursor; beginning at 0"); }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var engine = scope.ServiceProvider.GetRequiredService<UebaEngine>();
                _cursor = await engine.ProcessAsync(_cursor, 500, ct);
                LastCycleAt = DateTime.UtcNow; Error = null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { Error = "UEBA cycle failed; baselines are retained."; logger.LogError(e, "UEBA cycle failed"); }
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch (OperationCanceledException) { break; }
        }
    }
}
