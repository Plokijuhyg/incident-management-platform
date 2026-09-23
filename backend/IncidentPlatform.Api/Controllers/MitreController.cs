using IncidentPlatform.Api.DTOs.Mitre;
using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/mitre")]
[Authorize]
public class MitreController : ControllerBase
{
    private readonly IMitreService _mitreService;

    public MitreController(IMitreService mitreService)
    {
        _mitreService = mitreService;
    }

    [HttpGet("techniques")]
    public async Task<ActionResult<List<MitreTechniqueResponse>>> GetTechniques(
        [FromQuery] string? tactic, [FromQuery] string? search,
        [FromQuery] bool includeSubTechniques = true, CancellationToken cancellationToken = default)
    {
        return Ok(await _mitreService.GetTechniquesAsync(tactic, search, includeSubTechniques, cancellationToken));
    }

    [HttpGet("techniques/{techniqueId}")]
    public async Task<ActionResult<MitreTechniqueResponse>> GetByTechniqueId(string techniqueId, CancellationToken cancellationToken)
    {
        return Ok(await _mitreService.GetByTechniqueIdAsync(techniqueId, cancellationToken));
    }

    [HttpGet("tactics")]
    public async Task<ActionResult<List<string>>> GetTactics(CancellationToken cancellationToken)
    {
        return Ok(await _mitreService.GetTacticsAsync(cancellationToken));
    }
}
