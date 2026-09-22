using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/incidents")]
[Authorize]
public class IncidentsController : ControllerBase
{
    private readonly IIncidentService _incidentService;

    public IncidentsController(IIncidentService incidentService)
    {
        _incidentService = incidentService;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<IncidentSummaryResponse>>> GetPaged(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 25, CancellationToken cancellationToken = default)
    {
        return Ok(await _incidentService.GetPagedAsync(page, pageSize, cancellationToken));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<IncidentDetailResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.GetByIdAsync(id, cancellationToken));
    }

    [HttpPost]
    public async Task<ActionResult<IncidentDetailResponse>> Create(
        [FromBody] IncidentCreateRequest request, CancellationToken cancellationToken)
    {
        var result = await _incidentService.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    [HttpPut("{id:int}")]
    public async Task<ActionResult<IncidentDetailResponse>> Update(
        int id, [FromBody] IncidentUpdateRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.UpdateAsync(id, request, cancellationToken));
    }

    [HttpPost("{id:int}/assign")]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<ActionResult<IncidentDetailResponse>> Assign(
        int id, [FromBody] AssignIncidentRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.AssignAsync(id, request, cancellationToken));
    }

    [HttpPost("{id:int}/status")]
    public async Task<ActionResult<IncidentDetailResponse>> ChangeStatus(
        int id, [FromBody] ChangeStatusRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.ChangeStatusAsync(id, request, cancellationToken));
    }

    [HttpPost("{id:int}/close")]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<ActionResult<IncidentDetailResponse>> Close(
        int id, [FromBody] CloseIncidentRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.CloseAsync(id, request, cancellationToken));
    }
}
