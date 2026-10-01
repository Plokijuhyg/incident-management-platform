using IncidentPlatform.Api.DTOs.Dashboard;

namespace IncidentPlatform.Api.Interfaces;

public interface IDashboardService
{
    Task<DashboardSummary> SummaryAsync(CancellationToken ct);
    Task<List<CountBucket>> BySeverityAsync(CancellationToken ct);
    Task<List<CountBucket>> ByStatusAsync(CancellationToken ct);
    Task<List<CountBucket>> ByCategoryAsync(CancellationToken ct);
    Task<List<TimeBucket>> OverTimeAsync(int days, string interval, CancellationToken ct);
    Task<List<CountBucket>> TopIocTypesAsync(CancellationToken ct);
    Task<List<TechniqueCount>> TopTechniquesAsync(int limit, CancellationToken ct);
    Task<DashboardMetrics> MetricsAsync(int periodDays, CancellationToken ct);
}
