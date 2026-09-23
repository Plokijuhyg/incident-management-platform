using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.IncidentSubResources;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class IncidentSubResourceService : IIncidentSubResourceService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public IncidentSubResourceService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    // ---------------------------------------------------------------
    // Comments
    // ---------------------------------------------------------------

    public async Task<List<CommentResponse>> GetCommentsAsync(int incidentId, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        return await _dbContext.IncidentComments
            .Where(c => c.IncidentId == incidentId)
            .OrderBy(c => c.CreatedAt)
            .Include(c => c.Author)
            .Select(c => new CommentResponse
            {
                Id = c.Id,
                AuthorId = c.AuthorId,
                AuthorName = c.Author.FullName,
                Body = c.Body,
                IsInternal = c.IsInternal,
                CreatedAt = c.CreatedAt,
                EditedAt = c.EditedAt
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<CommentResponse> AddCommentAsync(int incidentId, CreateCommentRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        var now = DateTime.UtcNow;
        var comment = new IncidentComment
        {
            IncidentId = incidentId,
            AuthorId = _currentUser.Id,
            Body = request.Body,
            IsInternal = request.IsInternal,
            CreatedAt = now,
            UpdatedAt = now
        };

        _dbContext.IncidentComments.Add(comment);
        await _dbContext.SaveChangesAsync(cancellationToken);
        await _dbContext.Entry(comment).Reference(c => c.Author).LoadAsync(cancellationToken);

        return new CommentResponse
        {
            Id = comment.Id,
            AuthorId = comment.AuthorId,
            AuthorName = comment.Author.FullName,
            Body = comment.Body,
            IsInternal = comment.IsInternal,
            CreatedAt = comment.CreatedAt,
            EditedAt = comment.EditedAt
        };
    }

    // ---------------------------------------------------------------
    // Timeline — sorted by OccurredAt (database-design.md §4.9), no
    // delete endpoint exists anywhere: the record is the point.
    // ---------------------------------------------------------------

    public async Task<List<TimelineEventResponse>> GetTimelineAsync(int incidentId, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        return await _dbContext.IncidentTimelineEvents
            .Where(e => e.IncidentId == incidentId)
            .OrderBy(e => e.OccurredAt)
            .Include(e => e.ActorUser)
            .Select(e => new TimelineEventResponse
            {
                Id = e.Id,
                EventType = e.EventType,
                Title = e.Title,
                Description = e.Description,
                OccurredAt = e.OccurredAt,
                RecordedAt = e.RecordedAt,
                ActorName = e.ActorUser != null ? e.ActorUser.FullName : null,
                IsSystemGenerated = e.IsSystemGenerated
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<TimelineEventResponse> AddTimelineEventAsync(int incidentId, CreateTimelineEventRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        var timelineEvent = new IncidentTimelineEvent
        {
            IncidentId = incidentId,
            EventType = request.EventType,
            Title = request.Title,
            Description = request.Description,
            OccurredAt = request.OccurredAt, // analyst-supplied; may predate now (§4.9)
            RecordedAt = DateTime.UtcNow,     // system-set, immutable
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        };

        _dbContext.IncidentTimelineEvents.Add(timelineEvent);
        await _dbContext.SaveChangesAsync(cancellationToken);
        await _dbContext.Entry(timelineEvent).Reference(e => e.ActorUser).LoadAsync(cancellationToken);

        return new TimelineEventResponse
        {
            Id = timelineEvent.Id,
            EventType = timelineEvent.EventType,
            Title = timelineEvent.Title,
            Description = timelineEvent.Description,
            OccurredAt = timelineEvent.OccurredAt,
            RecordedAt = timelineEvent.RecordedAt,
            ActorName = timelineEvent.ActorUser?.FullName,
            IsSystemGenerated = timelineEvent.IsSystemGenerated
        };
    }

    // ---------------------------------------------------------------
    // Response Actions
    // ---------------------------------------------------------------

    public async Task<List<ResponseActionResponse>> GetResponseActionsAsync(int incidentId, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        return await _dbContext.ResponseActions
            .Where(r => r.IncidentId == incidentId)
            .OrderByDescending(r => r.PlannedAt ?? r.PerformedAt)
            .Include(r => r.PerformedBy)
            .Select(r => ToResponse(r))
            .ToListAsync(cancellationToken);
    }

    public async Task<ResponseActionResponse> AddResponseActionAsync(int incidentId, CreateResponseActionRequest request, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        if (request.TargetAssetId is not null)
        {
            var assetExists = await _dbContext.Assets.AnyAsync(a => a.Id == request.TargetAssetId, cancellationToken);
            if (!assetExists) throw new NotFoundException("Asset", request.TargetAssetId);
        }

        var action = new ResponseAction
        {
            IncidentId = incidentId,
            ActionType = request.ActionType,
            Description = request.Description,
            TargetType = request.TargetType,
            TargetValue = request.TargetValue,
            TargetAssetId = request.TargetAssetId,
            Status = ResponseActionStatus.Planned,
            PerformedById = _currentUser.Id,
            PlannedAt = DateTime.UtcNow
        };

        _dbContext.ResponseActions.Add(action);

        _dbContext.IncidentTimelineEvents.Add(new IncidentTimelineEvent
        {
            IncidentId = incidentId,
            EventType = TimelineEventType.ContainmentAction,
            Title = $"Response action planned: {request.ActionType}",
            Description = request.Description,
            OccurredAt = DateTime.UtcNow,
            RecordedAt = DateTime.UtcNow,
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
        await _dbContext.Entry(action).Reference(a => a.PerformedBy).LoadAsync(cancellationToken);

        return ToResponse(action);
    }

    public async Task<ResponseActionResponse> UpdateResponseActionAsync(int incidentId, int actionId, UpdateResponseActionRequest request, CancellationToken cancellationToken = default)
    {
        var action = await _dbContext.ResponseActions
            .Include(r => r.PerformedBy)
            .SingleOrDefaultAsync(r => r.Id == actionId && r.IncidentId == incidentId, cancellationToken)
            ?? throw new NotFoundException("ResponseAction", actionId);

        action.Status = request.Status;
        action.Result = request.Result;

        var now = DateTime.UtcNow;
        switch (request.Status)
        {
            case ResponseActionStatus.InProgress when action.PerformedAt is null:
                action.PerformedAt = now;
                break;
            case ResponseActionStatus.Completed or ResponseActionStatus.Failed or ResponseActionStatus.RolledBack
                when action.CompletedAt is null:
                action.CompletedAt = now;
                break;
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(action);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private async Task EnsureIncidentExistsAsync(int incidentId, CancellationToken cancellationToken)
    {
        var exists = await _dbContext.Incidents.AnyAsync(i => i.Id == incidentId, cancellationToken);
        if (!exists) throw new NotFoundException("Incident", incidentId);
    }

    private static ResponseActionResponse ToResponse(ResponseAction r) => new()
    {
        Id = r.Id,
        ActionType = r.ActionType,
        Description = r.Description,
        TargetType = r.TargetType,
        TargetValue = r.TargetValue,
        TargetAssetId = r.TargetAssetId,
        Status = r.Status,
        Result = r.Result,
        PerformedByName = r.PerformedBy?.FullName ?? string.Empty,
        PlannedAt = r.PlannedAt,
        PerformedAt = r.PerformedAt,
        CompletedAt = r.CompletedAt
    };
}
