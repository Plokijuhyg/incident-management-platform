using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;

namespace IncidentPlatform.Api.Interfaces;

public interface IIncidentService
{
    Task<PagedResult<IncidentSummaryResponse>> GetPagedAsync(IncidentQuery query, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> CreateAsync(IncidentCreateRequest request, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> UpdateAsync(int id, IncidentUpdateRequest request, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> AssignAsync(int id, AssignIncidentRequest request, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> ChangeStatusAsync(int id, ChangeStatusRequest request, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> CloseAsync(int id, CloseIncidentRequest request, CancellationToken cancellationToken = default);
}