using IncidentPlatform.Api.DTOs.Assets;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/assets")]
[Authorize]
public class AssetsController : ControllerBase
{
    private readonly IAssetService _assetService;

    public AssetsController(IAssetService assetService)
    {
        _assetService = assetService;
    }

    [HttpGet]
    public async Task<ActionResult<PagedResult<AssetResponse>>> GetPaged(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 25, CancellationToken cancellationToken = default)
    {
        return Ok(await _assetService.GetPagedAsync(page, pageSize, cancellationToken));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<AssetDetailResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        return Ok(await _assetService.GetByIdAsync(id, cancellationToken));
    }

    [HttpPost]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<ActionResult<AssetResponse>> Create([FromBody] AssetCreateRequest request, CancellationToken cancellationToken)
    {
        var result = await _assetService.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    [HttpPut("{id:int}")]
    [Authorize(Roles = $"{RoleNames.SecurityManager},{RoleNames.Admin}")]
    public async Task<ActionResult<AssetResponse>> Update(int id, [FromBody] AssetUpdateRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _assetService.UpdateAsync(id, request, cancellationToken));
    }
}
