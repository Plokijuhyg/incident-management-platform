using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Alerts;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Mapping;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class AlertService : IAlertService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public AlertService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    public async Task<PagedResult<AlertSummaryResponse>> GetPagedAsync(int page, int pageSize, AlertStatus? status, AlertSource? source, CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _dbContext.Alerts.AsQueryable();

        if (status is not null) query = query.Where(a => a.Status == status);
        if (source is not null) query = query.Where(a => a.Source == source);

        query = query.OrderByDescending(a => a.DetectedAt);

        var totalCount = await query.CountAsync(cancellationToken);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AlertSummaryResponse
            {
                Id = a.Id,
                Title = a.Title,
                Source = a.Source,
                Severity = a.Severity,
                Status = a.Status,
                IncidentId = a.IncidentId,
                DetectedAt = a.DetectedAt
            })
            .ToListAsync(cancellationToken);

        return new PagedResult<AlertSummaryResponse> { Items = items, Page = page, PageSize = pageSize, TotalCount = totalCount };
    }

    public async Task<AlertDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var alert = await FindOrThrowAsync(id, cancellationToken);
        return ToDetailResponse(alert);
    }

    public async Task<AlertDetailResponse> CreateAsync(AlertCreateRequest request, CancellationToken cancellationToken = default)
    {
        var alert = new Alert
        {
            Title = request.Title,
            Description = request.Description,
            Source = request.Source,
            Severity = request.Severity,
            Status = AlertStatus.New,
            RawPayload = request.RawPayload,
            DetectedAt = request.DetectedAt,
            ReceivedAt = DateTime.UtcNow
        };

        _dbContext.Alerts.Add(alert);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToDetailResponse(alert);
    }

    public async Task<IncidentDetailResponse> PromoteAsync(int id, PromoteAlertRequest request, CancellationToken cancellationToken = default)
    {
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        var alert = await _dbContext.Alerts.FromSqlInterpolated($"SELECT * FROM Alerts WHERE Id={id} FOR UPDATE").SingleOrDefaultAsync(cancellationToken)
            ?? throw new NotFoundException("Alert", id);

        if (alert.Status is AlertStatus.Promoted or AlertStatus.FalsePositive or AlertStatus.Closed)
        {
            throw new ConflictException($"Alert is already {alert.Status} and cannot be promoted.");
        }

        // One transaction: create incident (race-safe numbering), link the
        // alert, mark it Promoted, write the ALERT_RECEIVED timeline event
        // — all or nothing (api-design.md §5).

        var incidentNumber = await IncidentNumberGenerator.GenerateNextAsync(_dbContext, cancellationToken);

        // Alert.Source and Incident.Source share the same member names for
        // every value an Alert can carry (Siem, Edr, Firewall, Ids,
        // EmailSecurity, Manual) — safe to map by name.
        var incidentSource = Enum.Parse<IncidentSource>(alert.Source.ToString());

        var incident = new Incident
        {
            EnrichmentJson = alert.EnrichmentJson,
            IncidentNumber = incidentNumber,
            Title = request.Title,
            Description = alert.Description ?? alert.Title,
            Severity = request.Severity,
            Priority = request.Priority,
            Status = IncidentStatus.New,
            Category = request.Category,
            Source = incidentSource,
            CreatedById = _currentUser.Id,
            DetectedAt = alert.DetectedAt,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Version = 0
        };

        _dbContext.Incidents.Add(incident);
        await _dbContext.SaveChangesAsync(cancellationToken); // generates incident.Id

        await SigmaIncidentReferences.CopyAsync(_dbContext, alert, incident.Id, _currentUser.Id, cancellationToken);

        alert.IncidentId = incident.Id;
        alert.Status = AlertStatus.Promoted;
        alert.TriagedById = _currentUser.Id;
        alert.TriagedAt = DateTime.UtcNow;

        _dbContext.IncidentTimelineEvents.Add(new IncidentTimelineEvent
        {
            IncidentId = incident.Id,
            EventType = TimelineEventType.AlertReceived,
            Title = $"Promoted from alert: {alert.Title}",
            Description = alert.Description,
            OccurredAt = alert.DetectedAt, // the alert's own detection time, not "now"
            RecordedAt = DateTime.UtcNow,
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        await _dbContext.Entry(incident).Reference(i => i.CreatedBy).LoadAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<AlertDetailResponse> MarkFalsePositiveAsync(int id, FalsePositiveRequest request, CancellationToken cancellationToken = default)
    {
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
        var alert = await _dbContext.Alerts.FromSqlInterpolated($"SELECT * FROM Alerts WHERE Id={id} FOR UPDATE").SingleOrDefaultAsync(cancellationToken)
            ?? throw new NotFoundException("Alert", id);

        if (alert.Status is AlertStatus.Promoted)
        {
            throw new ConflictException("Alert was already promoted to an incident and cannot be marked as a false positive.");
        }

        alert.Status = AlertStatus.FalsePositive;
        alert.TriagedById = _currentUser.Id;
        alert.TriagedAt = DateTime.UtcNow;
        alert.Description = string.IsNullOrWhiteSpace(alert.Description)
            ? $"False positive: {request.Reason}"
            : $"{alert.Description}\n\nFalse positive: {request.Reason}";

        await _dbContext.SaveChangesAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return ToDetailResponse(alert);
    }

    private async Task<Alert> FindOrThrowAsync(int id, CancellationToken cancellationToken)
    {
        var alert = await _dbContext.Alerts.SingleOrDefaultAsync(a => a.Id == id, cancellationToken);
        return alert ?? throw new NotFoundException("Alert", id);
    }

    private static AlertDetailResponse ToDetailResponse(Alert a) => new()
    {
        RecommendedAction = ResponseRecommendations.For(a),
        Id = a.Id,
        Title = a.Title,
        Description = a.Description,
        Source = a.Source,
        SourceRuleId = a.SourceRuleId,
        Severity = a.Severity,
        Status = a.Status,
        RawPayload = a.RawPayload,
        IncidentId = a.IncidentId,
        DetectedAt = a.DetectedAt,
        ReceivedAt = a.ReceivedAt,
        TriagedAt = a.TriagedAt
    };
}