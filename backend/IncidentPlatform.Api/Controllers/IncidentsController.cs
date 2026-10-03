using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.IncidentSubResources;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.DTOs.Mitre;
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
    private readonly IMitreService _mitreService;
    private readonly IIncidentSubResourceService _subResourceService;

    public IncidentsController(
        IIncidentService incidentService, IIocService iocService,
        IAssetService assetService, IMitreService mitreService,
        IIncidentSubResourceService subResourceService)
    {
        _incidentService = incidentService;
        _iocService = iocService;
        _assetService = assetService;
        _mitreService = mitreService;
        _subResourceService = subResourceService;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<IncidentSummaryResponse>>> GetPaged(
        [FromQuery] IncidentQuery query, CancellationToken cancellationToken = default)
    {
        return Ok(await _incidentService.GetPagedAsync(query, cancellationToken));
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

    [HttpPost("{id:int}/escalate")]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<ActionResult<IncidentDetailResponse>> Escalate(
        int id, [FromBody] EscalateIncidentRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _incidentService.EscalateAsync(id, request, cancellationToken));
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

    [HttpPost("{id:int}/mitre-techniques")]
    public async Task<IActionResult> LinkMitreTechnique(
        int id, [FromBody] LinkMitreTechniqueRequest request, CancellationToken cancellationToken)
    {
        await _mitreService.LinkToIncidentAsync(id, request, cancellationToken);
        return NoContent();
    }

    [HttpDelete("{id:int}/mitre-techniques/{techniqueId:int}")]
    public async Task<IActionResult> UnlinkMitreTechnique(int id, int techniqueId, CancellationToken cancellationToken)
    {
        await _mitreService.UnlinkFromIncidentAsync(id, techniqueId, cancellationToken);
        return NoContent();
    }

    [HttpGet("{id:int}/comments")]
    public async Task<ActionResult<List<CommentResponse>>> GetComments(int id, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.GetCommentsAsync(id, cancellationToken));
    }

    [HttpPost("{id:int}/comments")]
    public async Task<ActionResult<CommentResponse>> AddComment(
        int id, [FromBody] CreateCommentRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.AddCommentAsync(id, request, cancellationToken));
    }

    [HttpGet("{id:int}/timeline")]
    public async Task<ActionResult<List<TimelineEventResponse>>> GetTimeline(int id, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.GetTimelineAsync(id, cancellationToken));
    }

    [HttpPost("{id:int}/timeline")]
    public async Task<ActionResult<TimelineEventResponse>> AddTimelineEvent(
        int id, [FromBody] CreateTimelineEventRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.AddTimelineEventAsync(id, request, cancellationToken));
    }

    [HttpGet("{id:int}/response-actions")]
    public async Task<ActionResult<List<ResponseActionResponse>>> GetResponseActions(int id, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.GetResponseActionsAsync(id, cancellationToken));
    }

    [HttpPost("{id:int}/response-actions")]
    public async Task<ActionResult<ResponseActionResponse>> AddResponseAction(
        int id, [FromBody] CreateResponseActionRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.AddResponseActionAsync(id, request, cancellationToken));
    }

    [HttpPut("{id:int}/response-actions/{actionId:int}")]
    public async Task<ActionResult<ResponseActionResponse>> UpdateResponseAction(
        int id, int actionId, [FromBody] UpdateResponseActionRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _subResourceService.UpdateResponseActionAsync(id, actionId, request, cancellationToken));
    }
}