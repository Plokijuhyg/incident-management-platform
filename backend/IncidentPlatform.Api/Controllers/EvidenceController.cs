using IncidentPlatform.Api.DTOs.Evidence;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

// Nested under /api/incidents to match api-design.md Â§4 â€” evidence has no
// independent existence outside its incident, and authorization is
// inherited from the parent.
[ApiController]
[Route("api/incidents/{incidentId:int}/evidence")]
[Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}")]
public class EvidenceController : ControllerBase
{
    private readonly IEvidenceService _evidenceService;

    public EvidenceController(IEvidenceService evidenceService)
    {
        _evidenceService = evidenceService;
    }

    [HttpGet]
    public async Task<ActionResult<List<EvidenceResponse>>> GetForIncident(int incidentId, CancellationToken cancellationToken)
    {
        return Ok(await _evidenceService.GetForIncidentAsync(incidentId, cancellationToken));
    }

    [HttpPost]
    [RequestSizeLimit(150 * 1024 * 1024)] // hard cap slightly above the configured 100MB default, real limit enforced in the service
    public async Task<ActionResult<EvidenceResponse>> Upload(
        int incidentId, IFormFile file, [FromForm] EvidenceType evidenceType, [FromForm] string? description,
        CancellationToken cancellationToken)
    {
        if (file.Length == 0)
        {
            return BadRequest("File is empty.");
        }

        await using var stream = file.OpenReadStream();

        var result = await _evidenceService.UploadAsync(
            incidentId, stream, file.FileName, file.ContentType, file.Length, evidenceType, description, cancellationToken);

        return Ok(result);
    }

    [HttpGet("{evidenceId:int}/download")]
    public async Task<IActionResult> Download(int incidentId, int evidenceId, CancellationToken cancellationToken)
    {
        var (stream, contentType, fileName) = await _evidenceService.DownloadAsync(incidentId, evidenceId, cancellationToken);
        return File(stream, contentType, fileName);
    }

    [HttpDelete("{evidenceId:int}")]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<IActionResult> Delete(int incidentId, int evidenceId, CancellationToken cancellationToken)
    {
        // Chain of custody â€” restricted (api-design.md Â§4).
        await _evidenceService.DeleteAsync(incidentId, evidenceId, cancellationToken);
        return NoContent();
    }
}
