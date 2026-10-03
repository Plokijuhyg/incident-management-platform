using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Mapping;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class IncidentService : IIncidentService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public IncidentService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    public async Task<PagedResult<IncidentSummaryResponse>> GetPagedAsync(IncidentQuery filter, CancellationToken cancellationToken = default)
    {
        var page = Math.Max(filter.Page, 1);
        var pageSize = Math.Clamp(filter.PageSize, 1, 100);

        var query = _dbContext.Incidents.AsQueryable();

        if (filter.Status is not null) query = query.Where(i => i.Status == filter.Status);
        if (filter.Severity is not null) query = query.Where(i => i.Severity == filter.Severity);
        if (filter.Priority is not null) query = query.Where(i => i.Priority == filter.Priority);
        if (filter.Category is not null) query = query.Where(i => i.Category == filter.Category);
        if (filter.Source is not null) query = query.Where(i => i.Source == filter.Source);
        if (filter.AssignedToId is not null) query = query.Where(i => i.AssignedToId == filter.AssignedToId);
        if (filter.Unassigned) query = query.Where(i => i.AssignedToId == null);
        if (filter.Tier is not null) query = query.Where(i => i.Tier == filter.Tier);
        if (filter.SlaBreached)
        {
            var now = DateTime.UtcNow;
            query = query.Where(i => i.SlaDueAt != null && i.SlaDueAt < now &&
                i.Status != IncidentStatus.Resolved && i.Status != IncidentStatus.Closed && i.Status != IncidentStatus.FalsePositive);
        }
        if (filter.OpenOnly)
        {
            query = query.Where(i => i.Status != IncidentStatus.Resolved &&
                i.Status != IncidentStatus.Closed && i.Status != IncidentStatus.FalsePositive);
        }
        if (filter.CreatedFrom is not null) query = query.Where(i => i.CreatedAt >= filter.CreatedFrom);
        if (filter.CreatedTo is not null) query = query.Where(i => i.CreatedAt <= filter.CreatedTo);
        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            var term = filter.Search.Trim();
            query = query.Where(i => i.Title.Contains(term) || i.IncidentNumber.Contains(term) || i.Description.Contains(term));
        }

        var totalCount = await query.CountAsync(cancellationToken);

        var sort = filter.Sort ?? IncidentQuery.DefaultSort;
        var descending = QueryOrdering.IsDescending(filter.Direction, defaultDescending: sort is "createdAt" or "updatedAt" or "severity" or "priority");
        var ordered = sort switch
        {
            "updatedAt" => query.OrderBy(i => i.UpdatedAt, descending),
            "severity" => query.OrderBy(QueryOrdering.ByEnumOrder<Incident, IncidentSeverity>(i => i.Severity), descending),
            "priority" => query.OrderBy(QueryOrdering.ByEnumOrder<Incident, IncidentPriority>(i => i.Priority), descending),
            "status" => query.OrderBy(QueryOrdering.ByEnumOrder<Incident, IncidentStatus>(i => i.Status), descending),
            "title" => query.OrderBy(i => i.Title, descending),
            "incidentNumber" => query.OrderBy(i => i.IncidentNumber, descending),
            _ => query.OrderBy(i => i.CreatedAt, descending)
        };
        // Stable paging when the sort key ties (same severity, same second).
        query = ordered.ThenByDescending(i => i.Id);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(i => new IncidentSummaryResponse
            {
                Id = i.Id,
                IncidentNumber = i.IncidentNumber,
                Title = i.Title,
                Severity = i.Severity,
                Priority = i.Priority,
                Status = i.Status,
                Category = i.Category,
                AssignedToName = i.AssignedTo != null ? i.AssignedTo.FullName : null,
                Tier = i.Tier,
                SlaDueAt = i.SlaDueAt,
                CreatedAt = i.CreatedAt
            })
            .ToListAsync(cancellationToken);

        return new PagedResult<IncidentSummaryResponse>
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };
    }

    public async Task<IncidentDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);
        var response = IncidentMapper.ToDetailResponse(incident);
        var alerts = await _dbContext.Alerts.AsNoTracking().Where(a=>a.IncidentId==id).ToListAsync(cancellationToken);
        response.RecommendedActions = alerts.Select(a=>(a, text:ResponseRecommendations.For(a))).Where(x=>x.text is not null).Select(x=>new RecommendedResponse(x.a.Id,x.a.SourceRuleId,x.text!)).ToList();
        return response;
    }

    public async Task<IncidentDetailResponse> CreateAsync(IncidentCreateRequest request, CancellationToken cancellationToken = default)
    {
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        var incidentNumber = await IncidentNumberGenerator.GenerateNextAsync(_dbContext, cancellationToken);

        var incident = new Incident
        {
            IncidentNumber = incidentNumber,
            Title = request.Title,
            Description = request.Description,
            Severity = request.Severity,
            Priority = request.Priority,
            Status = IncidentStatus.New,
            Category = request.Category,
            Source = request.Source,
            CreatedById = _currentUser.Id,
            OccurredAt = request.OccurredAt,
            DetectedAt = request.DetectedAt,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Tier = 1,
            SlaDueAt = CaseSla.DueAt(request.Severity, DateTime.UtcNow),
            Version = 0
        };

        _dbContext.Incidents.Add(incident);
        await _dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        await _dbContext.Entry(incident).Reference(i => i.CreatedBy).LoadAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> UpdateAsync(int id, IncidentUpdateRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        EnforceModifyPermission(incident);

        if (incident.Version != request.Version)
        {
            throw new ConflictException("This incident was modified by someone else. Reload and try again.");
        }

        incident.Title = request.Title;
        incident.Description = request.Description;
        incident.Severity = request.Severity;
        incident.Priority = request.Priority;
        incident.Category = request.Category;
        incident.UpdatedAt = DateTime.UtcNow;
        incident.Version++;

        await SaveWithConcurrencyCheckAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> AssignAsync(int id, AssignIncidentRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        var assigneeExists = await _dbContext.Users.AnyAsync(u => u.Id == request.AssignedToId && u.IsActive, cancellationToken);
        if (!assigneeExists)
        {
            throw new NotFoundException("User", request.AssignedToId);
        }

        incident.AssignedToId = request.AssignedToId;
        incident.UpdatedAt = DateTime.UtcNow;
        incident.Version++;

        await AddTimelineEventAsync(incident.Id, TimelineEventType.Assignment,
            "Incident assigned", $"Assigned to user {request.AssignedToId}", cancellationToken);

        await SaveWithConcurrencyCheckAsync(cancellationToken);
        await _dbContext.Entry(incident).Reference(i => i.AssignedTo).LoadAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> ChangeStatusAsync(int id, ChangeStatusRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        EnforceModifyPermission(incident);

        // Closing goes through CloseAsync (manager/admin, resolution summary required),
        // so reopening a closed incident is held to the same roles.
        if (incident.Status == IncidentStatus.Closed && request.Status != IncidentStatus.Closed &&
            !_currentUser.IsInRole(RoleNames.Admin) && !_currentUser.IsInRole(RoleNames.SecurityManager))
        {
            throw new ForbiddenException("Only managers and admins can reopen a closed incident.");
        }

        var previousStatus = incident.Status;
        incident.Status = request.Status;
        if (previousStatus == IncidentStatus.Closed && request.Status != IncidentStatus.Closed)
        {
            incident.ClosedAt = null;
        }
        incident.UpdatedAt = DateTime.UtcNow;
        incident.Version++;

        var now = DateTime.UtcNow;
        switch (request.Status)
        {
            case IncidentStatus.Triaged when incident.TriagedAt is null:
                incident.TriagedAt = now;
                break;
            case IncidentStatus.Contained when incident.ContainedAt is null:
                incident.ContainedAt = now;
                break;
            case IncidentStatus.Resolved when incident.ResolvedAt is null:
                incident.ResolvedAt = now;
                break;
        }

        await AddTimelineEventAsync(incident.Id, TimelineEventType.StatusChange,
            $"Status changed: {previousStatus} → {request.Status}", request.Note, cancellationToken);

        await SaveWithConcurrencyCheckAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> CloseAsync(int id, CloseIncidentRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        incident.Status = IncidentStatus.Closed;
        incident.ResolutionSummary = request.ResolutionSummary;
        incident.ClosedAt = DateTime.UtcNow;
        incident.UpdatedAt = DateTime.UtcNow;
        incident.Version++;

        await AddTimelineEventAsync(incident.Id, TimelineEventType.Resolution,
            "Incident closed", request.ResolutionSummary, cancellationToken);

        await SaveWithConcurrencyCheckAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> EscalateAsync(int id, EscalateIncidentRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        if (request.Tier < 1 || request.Tier > 3)
            throw new ValidationAppException("Tier must be 1, 2 or 3.");
        if (request.Tier < incident.Tier)
            throw new ValidationAppException("Escalation can only raise the tier; de-escalation is not supported.");
        if (request.Tier == incident.Tier && request.AssignedToId is null)
            throw new ValidationAppException("Choose a higher tier, an assignee, or both.");

        if (request.AssignedToId is not null)
        {
            var assigneeExists = await _dbContext.Users.AnyAsync(u => u.Id == request.AssignedToId && u.IsActive, cancellationToken);
            if (!assigneeExists) throw new NotFoundException("User", request.AssignedToId.Value);
            incident.AssignedToId = request.AssignedToId;
        }

        var previousTier = incident.Tier;
        incident.Tier = request.Tier;
        if (request.Tier > previousTier) incident.EscalatedAt = DateTime.UtcNow;
        incident.UpdatedAt = DateTime.UtcNow;
        incident.Version++;

        await AddTimelineEventAsync(incident.Id, TimelineEventType.Escalation,
            request.Tier > previousTier ? $"Escalated to Tier {request.Tier}" : "Reassigned", request.Note, cancellationToken);

        await SaveWithConcurrencyCheckAsync(cancellationToken);
        await _dbContext.Entry(incident).Reference(i => i.AssignedTo).LoadAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    private async Task<Incident> FindIncidentOrThrowAsync(int id, CancellationToken cancellationToken)
    {
        var incident = await _dbContext.Incidents
            .Include(i => i.CreatedBy)
            .Include(i => i.AssignedTo)
            .SingleOrDefaultAsync(i => i.Id == id, cancellationToken);

        return incident ?? throw new NotFoundException("Incident", id);
    }

    private void EnforceModifyPermission(Incident incident)
    {
        if (_currentUser.IsInRole(RoleNames.Admin) || _currentUser.IsInRole(RoleNames.SecurityManager))
        {
            return;
        }

        if (incident.AssignedToId != _currentUser.Id)
        {
            throw new ForbiddenException("You may only modify incidents assigned to you.");
        }
    }

    private async Task AddTimelineEventAsync(int incidentId, TimelineEventType type, string title, string? description, CancellationToken cancellationToken)
    {
        _dbContext.IncidentTimelineEvents.Add(new IncidentTimelineEvent
        {
            IncidentId = incidentId,
            EventType = type,
            Title = title,
            Description = description,
            OccurredAt = DateTime.UtcNow,
            RecordedAt = DateTime.UtcNow,
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        });

        await Task.CompletedTask;
    }

    private async Task SaveWithConcurrencyCheckAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ConflictException("This incident was modified by someone else. Reload and try again.");
        }
    }
}
