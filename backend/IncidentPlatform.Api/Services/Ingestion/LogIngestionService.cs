using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services.Ingestion;

public sealed record IngestResult(int Accepted, int Duplicates, int Alerts, int Blank);

public interface ILogIngestionService
{
    Task<IngestResult> IngestAsync(string source, LogFormat format, IReadOnlyList<string> lines, CancellationToken ct);
}

/// <summary>
/// The ingestion pipeline for non-Windows sources: Raw → Parse → Normalize →
/// Enrich → detect, then persist. Stores the original line verbatim, deduplicates
/// by fingerprint, matches source/destination IPs against the malicious-IOC
/// catalog (threat-intel enrichment), and raises alerts through the same path as
/// every other source, so an ingested log can become an incident.
/// </summary>
public sealed class LogIngestionService(AppDbContext db, IAuditContext audit) : ILogIngestionService
{
    private const int MaxRawLength = 32 * 1024;

    public async Task<IngestResult> IngestAsync(string source, LogFormat format, IReadOnlyList<string> lines, CancellationToken ct)
    {
        var received = DateTime.UtcNow;
        var blank = 0;

        // Raw → Parse → Normalize.
        var normalized = new List<LogEvent>(lines.Count);
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) { blank++; continue; }
            var raw = line.Length > MaxRawLength ? line[..MaxRawLength] : line;
            var parsed = LogParsers.Parse(format, raw);
            normalized.Add(LogNormalizer.Normalize(source, format, raw, parsed, received));
        }

        // Deduplicate within the batch and against what is already stored.
        var unique = normalized
            .GroupBy(e => e.Fingerprint).Select(g => g.First()).ToList();
        var fingerprints = unique.Select(e => e.Fingerprint).ToArray();
        var known = await db.LogEvents.AsNoTracking()
            .Where(e => fingerprints.Contains(e.Fingerprint))
            .Select(e => e.Fingerprint).ToListAsync(ct);
        var fresh = unique.Where(e => !known.Contains(e.Fingerprint)).ToList();
        var duplicates = normalized.Count - fresh.Count;

        // Enrich: one catalog lookup for every IP in the batch.
        await EnrichAsync(fresh, ct);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var accepted = 0;
        var alertsCreated = 0;
        foreach (var e in fresh)
        {
            db.LogEvents.Add(e);
            var alert = IngestionRules.Evaluate(e);
            if (alert is not null)
            {
                var existing = await db.Alerts.FirstOrDefaultAsync(a => a.DeduplicationKey == alert.DeduplicationKey, ct);
                if (existing is null)
                {
                    db.Alerts.Add(alert);
                    await db.SaveChangesAsync(ct); // generates alert.Id; LogEvents persist too but are not per-row audited
                    e.AlertId = alert.Id;
                    alertsCreated++;
                }
                else e.AlertId = existing.Id;
            }
            accepted++;
        }

        if (audit.IsActive)
            db.AuditLogs.Add(audit.Create("LOG_BATCH_INGESTED", "LogSource", source, AuditOutcome.Success,
                JsonSerializer.Serialize(new { source, format = format.ToString(), received, accepted, duplicates, alerts = alertsCreated, blank })));

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        return new IngestResult(accepted, duplicates, alertsCreated, blank);
    }

    private async Task EnrichAsync(List<LogEvent> events, CancellationToken ct)
    {
        var ips = events
            .SelectMany(e => new[] { e.SourceIp, e.DestinationIp })
            .Where(ip => !string.IsNullOrEmpty(ip))
            .Select(ip => ip!)
            .Distinct()
            .ToArray();
        if (ips.Length == 0) return;

        var malicious = await db.Iocs.AsNoTracking()
            .Where(i => i.Type == IocType.IpAddress && i.IsMalicious == true && ips.Contains(i.Value))
            .Select(i => new { i.Id, i.Value, i.Confidence })
            .ToListAsync(ct);
        if (malicious.Count == 0) return;

        var byValue = malicious.ToDictionary(i => i.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var e in events)
        {
            var hits = new[] { (field: "sourceIp", ip: e.SourceIp), (field: "destinationIp", ip: e.DestinationIp) }
                .Where(x => x.ip is not null && byValue.ContainsKey(x.ip))
                .Select(x => new
                {
                    x.field, indicator = x.ip, byValue[x.ip!].Id,
                    confidence = byValue[x.ip!].Confidence.ToString()
                })
                .ToList();
            if (hits.Count == 0) continue;
            e.Enriched = true;
            e.EnrichmentJson = JsonSerializer.Serialize(new { provider = "ioc-catalog", matches = hits });
        }
    }
}
