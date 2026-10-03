using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services.Ueba;

/// <summary>
/// User/entity behavior analytics over ingested logs and live Windows sign-ins.
/// Deliberately simple and explainable: per-user rolling baselines (failed-login
/// counts, seen source IPs) and two anomalies — a failed-login spike and a login
/// from a never-before-seen source. Anomalies become <see cref="AlertSource.Ueba"/>
/// alerts carrying the entity, so they flow into correlation like any other alert.
/// Both the generic ingestion store (<see cref="LogEvent"/>) and Windows Security
/// logon events (4624 success / 4625 failure) fold into the same baselines through
/// <see cref="FoldAsync"/>. Not a black-box model, and a flag is a lead to
/// investigate, never proof of compromise.
/// </summary>
public sealed class UebaEngine(AppDbContext db)
{
    public const int FailedLoginThreshold = 5;
    public const int LearningEvents = 10;
    private const int MaxIpSet = 50;

    // A source-independent view of one authentication-relevant event. Primary marks
    // the generic log store, whose row id doubles as the profile's LastEventId.
    private readonly record struct Signal(
        long Id, string User, string? SourceIp, string? Host, bool IsLogin,
        string? Outcome, DateTime EventTime, DateTime ReceivedAt, string Fingerprint, bool Primary);

    /// <summary>Folds new generic log events into baselines and raises anomaly alerts. Returns the new cursor.</summary>
    public async Task<long> ProcessAsync(long fromEventId, int maxBatch, CancellationToken ct)
    {
        var events = await db.LogEvents.AsNoTracking()
            .Where(e => e.Id > fromEventId && e.User != null)
            .OrderBy(e => e.Id).Take(maxBatch).ToListAsync(ct);
        if (events.Count == 0) return fromEventId;

        var signals = events.Select(e => new Signal(
            e.Id, e.User!, e.SourceIp, e.Host, IsLogin(e.Action), e.Outcome,
            e.EventTime, e.ReceivedAt, e.Fingerprint, Primary: true)).ToList();
        await FoldAsync(signals, ct);
        return events[^1].Id;
    }

    /// <summary>
    /// Folds new Windows Security logon events (4624 success, 4625 failure) into the
    /// same baselines. The account and source IP come from the event XML. Returns the
    /// new cursor; it advances past rows that are skipped as noise so they are not re-read.
    /// </summary>
    public async Task<long> ProcessWindowsAsync(long fromEventId, int maxBatch, CancellationToken ct)
    {
        var events = await db.WindowsEvents.AsNoTracking()
            .Where(e => e.Id > fromEventId && (e.EventId == 4624 || e.EventId == 4625))
            .OrderBy(e => e.Id).Take(maxBatch).ToListAsync(ct);
        if (events.Count == 0) return fromEventId;

        var signals = new List<Signal>();
        foreach (var e in events)
        {
            var (user, ip) = ParseLogon(e.RawXml);
            if (user is null) continue; // service/computer account or unparsable; cursor still advances
            signals.Add(new Signal(
                e.Id, user, ip, e.Machine, IsLogin: true,
                Outcome: e.EventId == 4624 ? "success" : "failure",
                EventTime: e.TimeCreated ?? e.ReceivedAt, ReceivedAt: e.ReceivedAt,
                Fingerprint: e.Fingerprint, Primary: false));
        }
        if (signals.Count > 0) await FoldAsync(signals, ct);
        return events[^1].Id;
    }

    private async Task FoldAsync(List<Signal> events, CancellationToken ct)
    {
        var users = events.Select(e => e.User).Distinct().ToList();
        var byUser = (await db.EntityProfiles.Where(p => p.EntityType == "user" && users.Contains(p.EntityValue)).ToListAsync(ct))
            .ToDictionary(p => p.EntityValue, StringComparer.OrdinalIgnoreCase);
        var raised = new HashSet<string>(StringComparer.Ordinal);
        var existingKeys = await db.Alerts
            .Where(a => a.Source == AlertSource.Ueba && a.DeduplicationKey != null && a.ReceivedAt >= DateTime.UtcNow.AddHours(-24))
            .Select(a => a.DeduplicationKey!).ToListAsync(ct);
        raised.UnionWith(existingKeys);

        foreach (var e in events)
        {
            var user = e.User;
            if (!byUser.TryGetValue(user, out var p))
            {
                p = new EntityProfile { EntityType = "user", EntityValue = user.Length > 255 ? user[..255] : user, FirstSeenAt = e.EventTime, WindowStart = e.EventTime, KnownSourceIpsJson = "[]", UpdatedAt = e.ReceivedAt };
                db.EntityProfiles.Add(p);
                byUser[user] = p;
            }
            p.LastSeenAt = e.EventTime;
            p.EventCount++;
            if (e.Primary) p.LastEventId = e.Id;
            if (e.EventTime >= p.WindowStart.AddHours(1)) { p.WindowStart = e.EventTime; p.FailedLoginsHour = 0; }

            var ips = Ips(p.KnownSourceIpsJson);
            var newIp = !string.IsNullOrEmpty(e.SourceIp) && !ips.Contains(e.SourceIp);

            if (e.IsLogin && e.Outcome == "failure")
            {
                p.FailedLoginsHour++;
                if (p.FailedLoginsHour >= FailedLoginThreshold)
                    Raise(p, "Failed-login spike", $"{p.FailedLoginsHour} failed logins within the hour for {user}.",
                        "High", "ueba:failspike:" + user.ToLowerInvariant() + ":" + p.WindowStart.Ticks, e, 60, raised);
            }
            if (e.IsLogin && e.Outcome == "success" && newIp && p.EventCount >= LearningEvents)
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
    }

    private void Raise(EntityProfile p, string title, string description, string severity, string dedupKey, Signal e, int riskDelta, HashSet<string> raised)
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

    // Pull the account and source IP out of a Windows 4624/4625 event. Namespace-agnostic
    // (matches local element names) so it works whatever XML framing the collector stored.
    // Returns a null user for service/computer accounts and loopback-only noise, so UEBA
    // tracks real interactive/remote users rather than the machine's own background logons.
    private static (string? User, string? Ip) ParseLogon(string rawXml)
    {
        if (string.IsNullOrWhiteSpace(rawXml)) return (null, null);
        try
        {
            var doc = XDocument.Parse(rawXml);
            var data = doc.Descendants().Where(d => d.Name.LocalName == "Data").ToList();
            string? Val(string name) => data.FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value;
            var user = Val("TargetUserName")?.Trim();
            var ip = Val("IpAddress")?.Trim();
            if (string.IsNullOrEmpty(user) || IsNoiseAccount(user)) return (null, null);
            if (string.IsNullOrEmpty(ip) || ip == "-" || ip == "::1" || ip == "127.0.0.1") ip = null;
            return (user, ip);
        }
        catch (XmlException) { return (null, null); }
    }

    private static bool IsNoiseAccount(string user)
    {
        if (user.EndsWith('$')) return true; // computer account
        return user.ToUpperInvariant() is "SYSTEM" or "LOCAL SERVICE" or "NETWORK SERVICE" or "ANONYMOUS LOGON" or "-";
    }

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
    private long _winCursor;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (environment.IsEnvironment("Testing")) return;
        // Forward-looking: start from the current tail of each source, don't backfill history on boot.
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            _cursor = await db.LogEvents.MaxAsync(e => (long?)e.Id, ct) ?? 0;
            _winCursor = await db.WindowsEvents.MaxAsync(e => (long?)e.Id, ct) ?? 0;
        }
        catch (Exception e) { logger.LogWarning(e, "UEBA could not read its start cursor; beginning at 0"); }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var engine = scope.ServiceProvider.GetRequiredService<UebaEngine>();
                _cursor = await engine.ProcessAsync(_cursor, 500, ct);
                _winCursor = await engine.ProcessWindowsAsync(_winCursor, 500, ct);
                LastCycleAt = DateTime.UtcNow; Error = null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { Error = "UEBA cycle failed; baselines are retained."; logger.LogError(e, "UEBA cycle failed"); }
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch (OperationCanceledException) { break; }
        }
    }
}
