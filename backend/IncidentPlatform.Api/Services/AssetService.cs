using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class AssetService : IAssetService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public AssetService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    public async Task<PagedResult<AssetResponse>> GetPagedAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _dbContext.Assets.OrderBy(a => a.Name).AsQueryable();
        var totalCount = await query.CountAsync(cancellationToken);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => ToResponse(a))
            .ToListAsync(cancellationToken);

        await EnrichSources(items,cancellationToken);
        return new PagedResult<AssetResponse> { Items = items, Page = page, PageSize = pageSize, TotalCount = totalCount };
    }

    public async Task<AssetDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var asset = await _dbContext.Assets.SingleOrDefaultAsync(a => a.Id == id, cancellationToken)
            ?? throw new NotFoundException("Asset", id);

        var appearances = await _dbContext.IncidentAssets
            .Where(ia => ia.AssetId == id)
            .Include(ia => ia.Incident)
            .Select(ia => new AssetIncidentAppearance
            {
                IncidentId = ia.IncidentId,
                IncidentNumber = ia.Incident.IncidentNumber,
                Title = ia.Incident.Title,
                ImpactType = ia.ImpactType,
                AddedAt = ia.AddedAt
            })
            .ToListAsync(cancellationToken);

        var response = ToResponse(asset);
        await EnrichSources([response],cancellationToken);
        return new AssetDetailResponse
        {
            LogEventCount=response.LogEventCount,LastEventAt=response.LastEventAt,CollectionStatus=response.CollectionStatus,
            Id = response.Id,
            Name = response.Name,
            Hostname = response.Hostname,
            IpAddress = response.IpAddress,
            Type = response.Type,
            OperatingSystem = response.OperatingSystem,
            Criticality = response.Criticality,
            Owner = response.Owner,
            Department = response.Department,
            IsActive = response.IsActive,
            Incidents = appearances
        };
    }

    public async Task<AssetResponse> CreateAsync(AssetCreateRequest request, CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrWhiteSpace(request.Hostname))
        {
            var duplicateHostname = await _dbContext.Assets.AnyAsync(a => a.Hostname == request.Hostname, cancellationToken);
            if (duplicateHostname)
            {
                throw new ConflictException($"An asset with hostname '{request.Hostname}' already exists.");
            }
        }

        var now = DateTime.UtcNow;

        var asset = new Asset
        {
            Name = request.Name,
            Hostname = request.Hostname,
            IpAddress = request.IpAddress,
            MacAddress = request.MacAddress,
            Type = request.Type,
            OperatingSystem = request.OperatingSystem,
            Criticality = request.Criticality,
            Owner = request.Owner,
            Department = request.Department,
            Location = request.Location,
            IsActive = true,
            CreatedAt = now,
            UpdatedAt = now
        };

        _dbContext.Assets.Add(asset);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(asset);
    }

    public async Task<AssetResponse> UpdateAsync(int id, AssetUpdateRequest request, CancellationToken cancellationToken = default)
    {
        var asset = await _dbContext.Assets.SingleOrDefaultAsync(a => a.Id == id, cancellationToken)
            ?? throw new NotFoundException("Asset", id);

        asset.Name = request.Name;
        asset.Criticality = request.Criticality;
        asset.Owner = request.Owner;
        asset.Department = request.Department;
        asset.IsActive = request.IsActive;
        asset.UpdatedAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(asset);
    }

    public async Task LinkToIncidentAsync(int incidentId, LinkAssetToIncidentRequest request, CancellationToken cancellationToken = default)
    {
        var incidentExists = await _dbContext.Incidents.AnyAsync(i => i.Id == incidentId, cancellationToken);
        if (!incidentExists)
        {
            throw new NotFoundException("Incident", incidentId);
        }

        var assetExists = await _dbContext.Assets.AnyAsync(a => a.Id == request.AssetId, cancellationToken);
        if (!assetExists)
        {
            throw new NotFoundException("Asset", request.AssetId);
        }

        var alreadyLinked = await _dbContext.IncidentAssets
            .AnyAsync(ia => ia.IncidentId == incidentId && ia.AssetId == request.AssetId, cancellationToken);
        if (alreadyLinked)
        {
            throw new ConflictException("This asset is already linked to this incident.");
        }

        _dbContext.IncidentAssets.Add(new IncidentAsset
        {
            IncidentId = incidentId,
            AssetId = request.AssetId,
            ImpactType = request.ImpactType,
            Notes = request.Notes,
            AddedById = _currentUser.Id,
            AddedAt = DateTime.UtcNow
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UnlinkFromIncidentAsync(int incidentId, int assetId, CancellationToken cancellationToken = default)
    {
        var link = await _dbContext.IncidentAssets
            .SingleOrDefaultAsync(ia => ia.IncidentId == incidentId && ia.AssetId == assetId, cancellationToken)
            ?? throw new NotFoundException("IncidentAsset link", $"{incidentId}/{assetId}");

        _dbContext.IncidentAssets.Remove(link);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task EnrichSources(List<AssetResponse> rows,CancellationToken ct)
    {
        var names=rows.Select(a=>a.Hostname??a.Name).ToArray();
        var stats=await _dbContext.WindowsEvents.Where(e=>names.Contains(e.Machine)).GroupBy(e=>e.Machine).Select(g=>new{Machine=g.Key,Count=g.Count(),Last=g.Max(e=>e.ReceivedAt)}).ToListAsync(ct);
        foreach(var row in rows){var s=stats.FirstOrDefault(s=>string.Equals(s.Machine,row.Hostname??row.Name,StringComparison.OrdinalIgnoreCase));if(s is null)continue;row.LogEventCount=s.Count;row.LastEventAt=s.Last;row.CollectionStatus=s.Last>DateTime.UtcNow.AddMinutes(-15)?"Logs received recently":"Stored logs; no recent events";}
    }

    private static AssetResponse ToResponse(Asset a) => new()
    {
        Id = a.Id,
        Name = a.Name,
        Hostname = a.Hostname,
        IpAddress = a.IpAddress,
        Type = a.Type,
        OperatingSystem = a.OperatingSystem,
        Criticality = a.Criticality,
        Owner = a.Owner,
        Department = a.Department,
        IsActive = a.IsActive
    };
}
