using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/incidents")]
[Authorize]
public class IncidentsController : ControllerBase
{
    private readonly IIncidentService _incidentService;
    private readonly IIocService _iocService;
    private readonly IAssetService _assetService;

    public IncidentsController(IIncidentService incidentService, IIocService iocService, IAssetService assetService)
    {
        _incidentService = incidentService;
        _iocService = iocService;
        _assetService = assetService;
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

    [HttpPost("{id:int}/iocs")]
    public async Task<ActionResult<LinkIocResult>> LinkIoc(
        int id, [FromBody] LinkIocToIncidentRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _iocService.LinkToIncidentAsync(id, request, cancellationToken));
    }

    [HttpDelete("{id:int}/iocs/{iocId:int}")]
    public async Task<IActionResult> UnlinkIoc(int id, int iocId, CancellationToken cancellationToken)
    {
        await _iocService.UnlinkFromIncidentAsync(id, iocId, cancellationToken);
        return NoContent();
    }

    [HttpPost("{id:int}/assets")]
    public async Task<IActionResult> LinkAsset(
        int id, [FromBody] LinkAssetToIncidentRequest request, CancellationToken cancellationToken)
    {
        await _assetService.LinkToIncidentAsync(id, request, cancellationToken);
        return NoContent();
    }

    [HttpDelete("{id:int}/assets/{assetId:int}")]
    public async Task<IActionResult> UnlinkAsset(int id, int assetId, CancellationToken cancellationToken)
    {
        await _assetService.UnlinkFromIncidentAsync(id, assetId, cancellationToken);
        return NoContent();
    }
}
