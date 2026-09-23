using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class IocService : IIocService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public IocService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    public async Task<PagedResult<IocResponse>> GetPagedAsync(int page, int pageSize, IocType? type, IocConfidence? confidence, bool? isMalicious, string? search, CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _dbContext.Iocs.AsQueryable();

        if (type is not null) query = query.Where(i => i.Type == type);
        if (confidence is not null) query = query.Where(i => i.Confidence == confidence);
        if (isMalicious is not null) query = query.Where(i => i.IsMalicious == isMalicious);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(i => i.Value.Contains(search));

        query = query.OrderByDescending(i => i.LastSeenAt);

        var totalCount = await query.CountAsync(cancellationToken);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(i => ToResponse(i))
            .ToListAsync(cancellationToken);

        return new PagedResult<IocResponse> { Items = items, Page = page, PageSize = pageSize, TotalCount = totalCount };
    }

    public async Task<IocDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var ioc = await _dbContext.Iocs.SingleOrDefaultAsync(i => i.Id == id, cancellationToken)
            ?? throw new NotFoundException("Ioc", id);

        // The correlation payoff (api-design.md §6): every incident this
        // indicator has appeared in.
        var appearances = await _dbContext.IncidentIocs
            .Where(ii => ii.IocId == id)
            .Include(ii => ii.Incident)
            .Select(ii => new IocIncidentAppearance
            {
                IncidentId = ii.IncidentId,
                IncidentNumber = ii.Incident.IncidentNumber,
                Title = ii.Incident.Title,
                Role = ii.Role,
                AddedAt = ii.AddedAt
            })
            .ToListAsync(cancellationToken);

        var response = ToResponse(ioc);
        return new IocDetailResponse
        {
            Id = response.Id,
            Type = response.Type,
            Value = response.Value,
            RawValue = response.RawValue,
            Confidence = response.Confidence,
            IsMalicious = response.IsMalicious,
            Source = response.Source,
            Description = response.Description,
            FirstSeenAt = response.FirstSeenAt,
            LastSeenAt = response.LastSeenAt,
            SightingCount = response.SightingCount,
            Incidents = appearances
        };
    }

    public async Task<IocResponse?> LookupAsync(IocType type, string value, CancellationToken cancellationToken = default)
    {
        var normalized = IocNormalizer.Normalize(type, value);

        var ioc = await _dbContext.Iocs
            .SingleOrDefaultAsync(i => i.Type == type && i.Value == normalized, cancellationToken);

        return ioc is null ? null : ToResponse(ioc);
    }

    public async Task<IocResponse> CreateAsync(IocCreateRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedValue = IocNormalizer.Normalize(request.Type, request.Value);

        var existing = await _dbContext.Iocs
            .SingleOrDefaultAsync(i => i.Type == request.Type && i.Value == normalizedValue, cancellationToken);

        if (existing is not null)
        {
            throw new ConflictException($"An IOC of type {request.Type} with this value already exists (id {existing.Id}).");
        }

        var now = DateTime.UtcNow;

        var ioc = new Ioc
        {
            Type = request.Type,
            Value = normalizedValue,
            RawValue = request.Value,
            Confidence = request.Confidence,
            IsMalicious = request.IsMalicious,
            Source = request.Source,
            Description = request.Description,
            FirstSeenAt = now,
            LastSeenAt = now,
            SightingCount = 0,
            CreatedById = _currentUser.Id,
            CreatedAt = now,
            UpdatedAt = now
        };

        _dbContext.Iocs.Add(ioc);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(ioc);
    }

    public async Task<IocResponse> UpdateAsync(int id, IocUpdateRequest request, CancellationToken cancellationToken = default)
    {
        var ioc = await _dbContext.Iocs.SingleOrDefaultAsync(i => i.Id == id, cancellationToken)
            ?? throw new NotFoundException("Ioc", id);

        ioc.Confidence = request.Confidence;
        ioc.IsMalicious = request.IsMalicious;
        ioc.Description = request.Description;
        ioc.UpdatedAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(ioc);
    }

    public async Task<LinkIocResult> LinkToIncidentAsync(int incidentId, LinkIocToIncidentRequest request, CancellationToken cancellationToken = default)
    {
        var incidentExists = await _dbContext.Incidents.AnyAsync(i => i.Id == incidentId, cancellationToken);
        if (!incidentExists)
        {
            throw new NotFoundException("Incident", incidentId);
        }

        var normalizedValue = IocNormalizer.Normalize(request.Type, request.Value);

        // Find-or-create the catalog entry, create the link, bump
        // SightingCount/LastSeenAt — one transaction, all-or-nothing
        // (database-design.md §3.1, api-design.md §4).
        await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        var ioc = await _dbContext.Iocs
            .SingleOrDefaultAsync(i => i.Type == request.Type && i.Value == normalizedValue, cancellationToken);

        var wasNewlyCreated = ioc is null;
        var now = DateTime.UtcNow;

        if (ioc is null)
        {
            ioc = new Ioc
            {
                Type = request.Type,
                Value = normalizedValue,
                RawValue = request.Value,
                Confidence = request.Confidence,
                IsMalicious = null,
                FirstSeenAt = now,
                LastSeenAt = now,
                SightingCount = 0,
                CreatedById = _currentUser.Id,
                CreatedAt = now,
                UpdatedAt = now
            };
            _dbContext.Iocs.Add(ioc);
            await _dbContext.SaveChangesAsync(cancellationToken); // generates ioc.Id
        }

        var alreadyLinked = await _dbContext.IncidentIocs
            .AnyAsync(ii => ii.IncidentId == incidentId && ii.IocId == ioc.Id, cancellationToken);

        if (alreadyLinked)
        {
            throw new ConflictException("This IOC is already linked to this incident.");
        }

        _dbContext.IncidentIocs.Add(new IncidentIoc
        {
            IncidentId = incidentId,
            IocId = ioc.Id,
            Role = request.Role,
            Notes = request.Notes,
            AddedById = _currentUser.Id,
            AddedAt = now
        });

        ioc.SightingCount++;
        ioc.LastSeenAt = now;

        await AddTimelineEventAsync(incidentId, $"IOC identified: {ioc.Value}", cancellationToken);

        await _dbContext.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new LinkIocResult { Ioc = ToResponse(ioc), WasNewlyCreated = wasNewlyCreated };
    }

    public async Task UnlinkFromIncidentAsync(int incidentId, int iocId, CancellationToken cancellationToken = default)
    {
        // Unlinks only — never deletes the catalog entry (api-design.md §4).
        var link = await _dbContext.IncidentIocs
            .SingleOrDefaultAsync(ii => ii.IncidentId == incidentId && ii.IocId == iocId, cancellationToken)
            ?? throw new NotFoundException("IncidentIoc link", $"{incidentId}/{iocId}");

        _dbContext.IncidentIocs.Remove(link);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task AddTimelineEventAsync(int incidentId, string title, CancellationToken cancellationToken)
    {
        _dbContext.IncidentTimelineEvents.Add(new IncidentTimelineEvent
        {
            IncidentId = incidentId,
            EventType = TimelineEventType.IocIdentified,
            Title = title,
            OccurredAt = DateTime.UtcNow,
            RecordedAt = DateTime.UtcNow,
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        });
        await Task.CompletedTask;
    }

    private static IocResponse ToResponse(Ioc i) => new()
    {
        Id = i.Id,
        Type = i.Type,
        Value = i.Value,
        RawValue = i.RawValue,
        Confidence = i.Confidence,
        IsMalicious = i.IsMalicious,
        Source = i.Source,
        Description = i.Description,
        FirstSeenAt = i.FirstSeenAt,
        LastSeenAt = i.LastSeenAt,
        SightingCount = i.SightingCount
    };
}
