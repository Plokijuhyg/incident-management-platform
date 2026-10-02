using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Logs;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services.Ingestion;

public interface ILogQueryService
{
    Task<PagedResult<LogSummaryResponse>> GetPagedAsync(LogQuery query, CancellationToken ct = default);
    Task<LogDetailResponse> GetByIdAsync(long id, CancellationToken ct = default);
    Task<LogSummaryStats> GetSummaryAsync(CancellationToken ct = default);
}

/// <summary>The analyst-facing read side of the ingestion pipeline: filter, search and sort the unified log store.</summary>
public sealed class LogQueryService(AppDbContext db) : ILogQueryService
{
    public async Task<PagedResult<LogSummaryResponse>> GetPagedAsync(LogQuery filter, CancellationToken ct = default)
    {
        var page = Math.Max(filter.Page, 1);
        var pageSize = Math.Clamp(filter.PageSize, 1, 100);

        var query = db.LogEvents.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(filter.Source)) query = query.Where(e => e.Source == filter.Source.Trim());
        if (filter.SourceType is not null) query = query.Where(e => e.SourceType == filter.SourceType);
        if (filter.MaxSeverity is not null) query = query.Where(e => e.Severity <= filter.MaxSeverity);
        if (!string.IsNullOrWhiteSpace(filter.Action)) query = query.Where(e => e.Action == filter.Action.Trim().ToLower());
        if (!string.IsNullOrWhiteSpace(filter.Outcome)) query = query.Where(e => e.Outcome == filter.Outcome.Trim().ToLower());
        if (!string.IsNullOrWhiteSpace(filter.User)) query = query.Where(e => e.User == filter.User.Trim());
        if (!string.IsNullOrWhiteSpace(filter.Ip))
        {
            var ip = filter.Ip.Trim();
            query = query.Where(e => e.SourceIp == ip || e.DestinationIp == ip);
        }
        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            var term = filter.Search.Trim();
            query = query.Where(e => e.Message.Contains(term));
        }
        if (filter.From is not null) query = query.Where(e => e.EventTime >= filter.From);
        if (filter.To is not null) query = query.Where(e => e.EventTime <= filter.To);
        if (filter.AlertsOnly) query = query.Where(e => e.AlertId != null);

        var totalCount = await query.CountAsync(ct);

        var sort = filter.Sort ?? LogQuery.DefaultSort;
        // Severity defaults to worst-first (ascending, since 0 is most severe); times default newest-first.
        var descending = QueryOrdering.IsDescending(filter.Direction, defaultDescending: sort is "eventTime" or "receivedAt");
        var ordered = sort switch
        {
            "receivedAt" => query.OrderBy(e => e.ReceivedAt, descending),
            "severity" => query.OrderBy(e => e.Severity, descending),
            "source" => query.OrderBy(e => e.Source, descending),
            _ => query.OrderBy(e => e.EventTime, descending),
        };
        query = ordered.ThenByDescending(e => e.Id);

        var items = await query
            .Skip((page - 1) * pageSize).Take(pageSize)
            .Select(e => new LogSummaryResponse
            {
                Id = e.Id, Source = e.Source, SourceType = e.SourceType, Host = e.Host,
                EventTime = e.EventTime, ReceivedAt = e.ReceivedAt, Severity = e.Severity,
                Action = e.Action, Outcome = e.Outcome, SourceIp = e.SourceIp, DestinationIp = e.DestinationIp,
                User = e.User, Message = e.Message, Enriched = e.Enriched, AlertId = e.AlertId,
            })
            .ToListAsync(ct);

        return new PagedResult<LogSummaryResponse> { Items = items, Page = page, PageSize = pageSize, TotalCount = totalCount };
    }

    public async Task<LogDetailResponse> GetByIdAsync(long id, CancellationToken ct = default)
    {
        var e = await db.LogEvents.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct)
            ?? throw new NotFoundException("Log event", (int)Math.Clamp(id, int.MinValue, int.MaxValue));
        return new LogDetailResponse
        {
            Id = e.Id, Source = e.Source, SourceType = e.SourceType, Host = e.Host,
            EventTime = e.EventTime, ReceivedAt = e.ReceivedAt, Severity = e.Severity,
            Action = e.Action, Outcome = e.Outcome, SourceIp = e.SourceIp, DestinationIp = e.DestinationIp,
            User = e.User, Message = e.Message, Enriched = e.Enriched, AlertId = e.AlertId,
            Facility = e.Facility, SourcePort = e.SourcePort, DestinationPort = e.DestinationPort,
            Protocol = e.Protocol, RawLog = e.RawLog, FieldsJson = e.FieldsJson, EnrichmentJson = e.EnrichmentJson,
        };
    }

    public async Task<LogSummaryStats> GetSummaryAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var events = db.LogEvents.AsNoTracking();
        var sources = await events
            .GroupBy(e => new { e.SourceType, e.Source })
            .Select(g => new LogSourceStat(
                g.Key.SourceType.ToString(), g.Key.Source, g.Count(), g.Max(e => (DateTime?)e.ReceivedAt)))
            .OrderByDescending(s => s.Count).Take(20)
            .ToListAsync(ct);

        return new LogSummaryStats(
            await events.CountAsync(ct),
            await events.MaxAsync(e => (DateTime?)e.ReceivedAt, ct),
            await events.CountAsync(e => e.ReceivedAt >= now.AddHours(-1), ct),
            await events.CountAsync(e => e.AlertId != null, ct),
            sources);
    }
}
