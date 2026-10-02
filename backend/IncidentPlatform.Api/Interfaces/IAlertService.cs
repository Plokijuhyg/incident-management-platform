using IncidentPlatform.Api.DTOs.Alerts;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Interfaces;

public interface IAlertService
{
    Task<PagedResult<AlertSummaryResponse>> GetPagedAsync(AlertQuery query, CancellationToken cancellationToken = default);

    Task<AlertDetailResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<AlertDetailResponse> CreateAsync(AlertCreateRequest request, CancellationToken cancellationToken = default);

    Task<IncidentDetailResponse> PromoteAsync(int id, PromoteAlertRequest request, CancellationToken cancellationToken = default);

    Task<AlertDetailResponse> MarkFalsePositiveAsync(int id, FalsePositiveRequest request, CancellationToken cancellationToken = default);
}