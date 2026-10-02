using IncidentPlatform.Api.DTOs.Alerts;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/alerts")]
[Authorize]
public class AlertsController : ControllerBase
{
    private readonly IAlertService _alertService;

    public AlertsController(IAlertService alertService)
    {
        _alertService = alertService;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<AlertSummaryResponse>>> GetPaged(
        [FromQuery] AlertQuery query, CancellationToken cancellationToken = default)
    {
        return Ok(await _alertService.GetPagedAsync(query, cancellationToken));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<AlertDetailResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        return Ok(await _alertService.GetByIdAsync(id, cancellationToken));
    }

    [HttpPost]
    public async Task<ActionResult<AlertDetailResponse>> Create([FromBody] AlertCreateRequest request, CancellationToken cancellationToken)
    {
        var result = await _alertService.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    [HttpPost("{id:int}/promote")]
    public async Task<ActionResult<IncidentDetailResponse>> Promote(int id, [FromBody] PromoteAlertRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _alertService.PromoteAsync(id, request, cancellationToken));
    }

    [HttpPost("{id:int}/false-positive")]
    public async Task<ActionResult<AlertDetailResponse>> FalsePositive(int id, [FromBody] FalsePositiveRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _alertService.MarkFalsePositiveAsync(id, request, cancellationToken));
    }
}