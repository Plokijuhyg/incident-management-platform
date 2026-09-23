using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Common;

namespace IncidentPlatform.Api.Interfaces;

public interface IAssetService
{
    Task<PagedResult<AssetResponse>> GetPagedAsync(int page, int pageSize, CancellationToken cancellationToken = default);

    Task<AssetDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<AssetResponse> CreateAsync(AssetCreateRequest request, CancellationToken cancellationToken = default);

    Task<AssetResponse> UpdateAsync(int id, AssetUpdateRequest request, CancellationToken cancellationToken = default);

    Task LinkToIncidentAsync(int incidentId, LinkAssetToIncidentRequest request, CancellationToken cancellationToken = default);

    Task UnlinkFromIncidentAsync(int incidentId, int assetId, CancellationToken cancellationToken = default);
}
