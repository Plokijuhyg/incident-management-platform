using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Interfaces;

public interface IIocService
{
    Task<PagedResult<IocResponse>> GetPagedAsync(int page, int pageSize, IocType? type, IocConfidence? confidence, bool? isMalicious, string? search, CancellationToken cancellationToken = default);

    Task<IocDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<IocResponse?> LookupAsync(IocType type, string value, CancellationToken cancellationToken = default);

    Task<IocResponse> CreateAsync(IocCreateRequest request, CancellationToken cancellationToken = default);

    Task<IocResponse> UpdateAsync(int id, IocUpdateRequest request, CancellationToken cancellationToken = default);

    Task<LinkIocResult> LinkToIncidentAsync(int incidentId, LinkIocToIncidentRequest request, CancellationToken cancellationToken = default);

    Task UnlinkFromIncidentAsync(int incidentId, int iocId, CancellationToken cancellationToken = default);
}
