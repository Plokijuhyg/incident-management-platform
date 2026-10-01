using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/dashboard")]
public sealed class DashboardController(IDashboardService dashboard) : ControllerBase
{
    [HttpGet("summary")]
    public async Task<IActionResult> Summary(CancellationToken ct) => Ok(await dashboard.SummaryAsync(ct));
    [HttpGet("incidents-by-severity")]
    public async Task<IActionResult> BySeverity(CancellationToken ct) => Ok(await dashboard.BySeverityAsync(ct));
    [HttpGet("incidents-by-status")]
    public async Task<IActionResult> ByStatus(CancellationToken ct) => Ok(await dashboard.ByStatusAsync(ct));
    [HttpGet("incidents-by-category")]
    public async Task<IActionResult> ByCategory(CancellationToken ct) => Ok(await dashboard.ByCategoryAsync(ct));
    [HttpGet("incidents-over-time")]
    public async Task<IActionResult> OverTime(int days = 30, string interval = "day", CancellationToken ct = default)
        => Ok(await dashboard.OverTimeAsync(days, interval, ct));
    [HttpGet("top-ioc-types")]
    public async Task<IActionResult> TopIocTypes(CancellationToken ct) => Ok(await dashboard.TopIocTypesAsync(ct));
    [HttpGet("top-mitre-techniques")]
    public async Task<IActionResult> TopTechniques(int limit = 10, CancellationToken ct = default)
        => Ok(await dashboard.TopTechniquesAsync(limit, ct));
    [HttpGet("metrics")]
    public async Task<IActionResult> Metrics(int periodDays = 30, CancellationToken ct = default)
        => Ok(await dashboard.MetricsAsync(periodDays, ct));
}
