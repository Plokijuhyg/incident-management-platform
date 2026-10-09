using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Users;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager},{RoleNames.SocAnalyst}")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
    }

    // api-design.md §6: GET /api/users/assignable is available to All
    // authenticated roles (populating an assignee dropdown), everything
    // else on this controller is Admin only.

    [HttpGet("api/users/assignable")]
    public async Task<ActionResult<List<AssignableUserResponse>>> GetAssignable(CancellationToken cancellationToken)
    {
        return Ok(await _userService.GetAssignableAsync(cancellationToken));
    }

    [HttpGet("api/roles")]
    public async Task<ActionResult<List<RoleResponse>>> GetRoles(CancellationToken cancellationToken)
    {
        return Ok(await _userService.GetRolesAsync(cancellationToken));
    }

    [HttpGet("api/users")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<ActionResult<PagedResult<UserResponse>>> GetPaged(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 25, CancellationToken cancellationToken = default)
    {
        return Ok(await _userService.GetPagedAsync(page, pageSize, cancellationToken));
    }

    [HttpGet("api/users/{id:int}")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<ActionResult<UserResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        return Ok(await _userService.GetByIdAsync(id, cancellationToken));
    }

    [HttpPost("api/users")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<ActionResult<UserResponse>> Create([FromBody] CreateUserRequest request, CancellationToken cancellationToken)
    {
        var result = await _userService.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = result.Id }, result);
    }

    [HttpPut("api/users/{id:int}")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<ActionResult<UserResponse>> Update(int id, [FromBody] UpdateUserRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _userService.UpdateAsync(id, request, cancellationToken));
    }

    [HttpPost("api/users/{id:int}/reset-password"),Authorize(Roles=RoleNames.Admin)]
    public async Task<IActionResult> ResetPassword(int id,ResetUserPasswordRequest request,CancellationToken ct)
    {
        await _userService.ResetPasswordAsync(id,request.Password,ct);return NoContent();
    }

    [HttpPost("api/users/{id:int}/deactivate")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<IActionResult> Deactivate(int id, CancellationToken cancellationToken)
    {
        await _userService.DeactivateAsync(id, cancellationToken);
        return NoContent();
    }

    [HttpPost("api/users/{id:int}/roles")]
    [Authorize(Roles = RoleNames.Admin)]
    public async Task<ActionResult<UserResponse>> ReplaceRoles(int id, [FromBody] ReplaceRolesRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _userService.ReplaceRolesAsync(id, request, cancellationToken));
    }
}
