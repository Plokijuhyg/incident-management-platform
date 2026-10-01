using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Dashboard;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public sealed class DashboardService(AppDbContext db, ICurrentUser currentUser) : IDashboardService
{
    private IQueryable<Incident> Incidents => db.Incidents.AsNoTracking();
    private IQueryable<Incident> Open => Incidents.Where(i => i.Status != IncidentStatus.Closed &&
        i.Status != IncidentStatus.Resolved && i.Status != IncidentStatus.FalsePositive);

    public async Task<DashboardSummary> SummaryAsync(CancellationToken ct)
    {
        var today = DateTime.UtcNow.Date;
        var tomorrow = today.AddDays(1);
        return new(await Incidents.CountAsync(ct), await Open.CountAsync(ct),
            await Open.CountAsync(i => i.Severity == IncidentSeverity.Critical, ct),
            await Open.CountAsync(i => i.AssignedToId == null, ct),
            await db.Alerts.CountAsync(a => a.Status == AlertStatus.New, ct),
            await Incidents.CountAsync(i => i.CreatedAt >= today && i.CreatedAt < tomorrow, ct),
            await Open.CountAsync(i => i.AssignedToId == currentUser.Id, ct));
    }

    private async Task<List<CountBucket>> Counts<T>(System.Linq.Expressions.Expression<Func<Incident,T>> field,CancellationToken ct) where T:struct,Enum
    {
        var counts=await Incidents.GroupBy(field).Select(g=>new{Key=g.Key,Count=g.Count()}).ToListAsync(ct);
        return Enum.GetValues<T>().Select(value=>new CountBucket(value.ToString(),counts.FirstOrDefault(x=>EqualityComparer<T>.Default.Equals(x.Key,value))?.Count??0)).ToList();
    }
    public Task<List<CountBucket>> BySeverityAsync(CancellationToken ct)=>Counts(i=>i.Severity,ct);
    public Task<List<CountBucket>> ByStatusAsync(CancellationToken ct)=>Counts(i=>i.Status,ct);
    public Task<List<CountBucket>> ByCategoryAsync(CancellationToken ct)=>Counts(i=>i.Category,ct);

    public async Task<List<TimeBucket>> OverTimeAsync(int days, string interval, CancellationToken ct)
    {
        CheckDays(days);
        if (interval is not ("day" or "week"))
            throw new ValidationAppException("interval must be 'day' or 'week'.");
        var width = interval == "week" ? 7 : 1;
        var end = DateTime.UtcNow.Date.AddDays(1);
        var start = end.AddDays(-days);
        // SQL groups directly into day/week buckets; only zero filling happens here.
        var aggregates = await Incidents.Where(i => i.CreatedAt >= start && i.CreatedAt < end)
            .GroupBy(i => (int)Math.Floor(EF.Functions.DateDiffDay(start, i.CreatedAt) / (double)width))
            .Select(g => new { Index = g.Key, Count = g.Count() }).ToListAsync(ct);
        var counts = aggregates.ToDictionary(g => g.Index, g => g.Count);
        return Enumerable.Range(0, (days + width - 1) / width)
            .Select(index => new TimeBucket(DateTime.SpecifyKind(start.AddDays(index * width), DateTimeKind.Utc),
                counts.GetValueOrDefault(index))).ToList();
    }

    public Task<List<CountBucket>> TopIocTypesAsync(CancellationToken ct) => db.Iocs.AsNoTracking()
        .GroupBy(i => i.Type).OrderByDescending(g => g.Count()).ThenBy(g => g.Key)
        .Select(g => new CountBucket(g.Key.ToString(), g.Count())).ToListAsync(ct);

    public Task<List<TechniqueCount>> TopTechniquesAsync(int limit, CancellationToken ct)
    {
        if (limit is < 1 or > 100) throw new ValidationAppException("limit must be between 1 and 100.");
        return db.IncidentMitreTechniques.AsNoTracking()
            .GroupBy(link => new { link.MitreTechnique.TechniqueId, link.MitreTechnique.Name })
            .OrderByDescending(g => g.Count()).ThenBy(g => g.Key.TechniqueId).Take(limit)
            .Select(g => new TechniqueCount(g.Key.TechniqueId, g.Key.Name, g.Count())).ToListAsync(ct);
    }

    public async Task<DashboardMetrics> MetricsAsync(int periodDays, CancellationToken ct)
    {
        CheckDays(periodDays);
        var now = DateTime.UtcNow;
        var start = now.AddDays(-periodDays);
        var period = Incidents.Where(i => i.CreatedAt >= start && i.CreatedAt <= now);
        var detection = period.Where(i => i.OccurredAt != null && i.DetectedAt != null && i.DetectedAt >= i.OccurredAt);
        var containment = period.Where(i => i.DetectedAt != null && i.ContainedAt != null && i.ContainedAt >= i.DetectedAt);
        var resolution = period.Where(i => i.DetectedAt != null && i.ResolvedAt != null && i.ResolvedAt >= i.DetectedAt);
        return new(
            await detection.AverageAsync(i => (double?)EF.Functions.DateDiffSecond(i.OccurredAt, i.DetectedAt) / 60.0, ct),
            await containment.AverageAsync(i => (double?)EF.Functions.DateDiffSecond(i.DetectedAt, i.ContainedAt) / 60.0, ct),
            await resolution.AverageAsync(i => (double?)EF.Functions.DateDiffSecond(i.DetectedAt, i.ResolvedAt) / 60.0, ct),
            await period.CountAsync(ct), periodDays,
            await detection.CountAsync(ct), await containment.CountAsync(ct), await resolution.CountAsync(ct));
    }

    private static void CheckDays(int days)
    {
        if (days is < 1 or > 365) throw new ValidationAppException("days must be between 1 and 365.");
    }
}
