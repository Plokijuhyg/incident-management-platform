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

    public async Task<PagedResult<IncidentSummaryResponse>> GetPagedAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _dbContext.Incidents
            .OrderByDescending(i => i.CreatedAt)
            .AsQueryable();

        var totalCount = await query.CountAsync(cancellationToken);

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
        return IncidentMapper.ToDetailResponse(incident);
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
            DetectedAt = request.DetectedAt,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
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

        await _dbContext.SaveChangesAsync(cancellationToken);
        await _dbContext.Entry(incident).Reference(i => i.AssignedTo).LoadAsync(cancellationToken);

        return IncidentMapper.ToDetailResponse(incident);
    }

    public async Task<IncidentDetailResponse> ChangeStatusAsync(int id, ChangeStatusRequest request, CancellationToken cancellationToken = default)
    {
        var incident = await FindIncidentOrThrowAsync(id, cancellationToken);

        EnforceModifyPermission(incident);

        var previousStatus = incident.Status;
        incident.Status = request.Status;
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

        await _dbContext.SaveChangesAsync(cancellationToken);

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

        await _dbContext.SaveChangesAsync(cancellationToken);

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
