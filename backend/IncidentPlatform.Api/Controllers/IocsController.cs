using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Iocs;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/iocs")]
[Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}")]
public class IocsController : ControllerBase
{
    private readonly IIocService _iocService;

    public IocsController(IIocService iocService)
    {
        _iocService = iocService;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<IocResponse>>> GetPaged(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 25,
        [FromQuery] IocType? type = null, [FromQuery] IocConfidence? confidence = null,
        [FromQuery] bool? isMalicious = null, [FromQuery] string? search = null,
        CancellationToken cancellationToken = default)
    {
        return Ok(await _iocService.GetPagedAsync(page, pageSize, type, confidence, isMalicious, search, cancellationToken));
    }

    [HttpGet("lookup")]
    public async Task<ActionResult<IocResponse>> Lookup([FromQuery] IocType type, [FromQuery] string value, CancellationToken cancellationToken)
    {
        var result = await _iocService.LookupAsync(type, value, cancellationToken);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<IocDetailResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        return Ok(await _iocService.GetByIdAsync(id, cancellationToken));
    }

    [HttpPost]
    public async Task<ActionResult<IocResponse>> Create([FromBody] IocCreateRequest request, CancellationToken cancellationToken)
    {
        var result = await _iocService.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    [HttpPut("{id:int}")]
    public async Task<ActionResult<IocResponse>> Update(int id, [FromBody] IocUpdateRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _iocService.UpdateAsync(id, request, cancellationToken));
    }
}
