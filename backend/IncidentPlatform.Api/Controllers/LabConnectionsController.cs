using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace IncidentPlatform.Api.Controllers;

[ApiController, Route("api/lab/connections"), Authorize(Roles = RoleNames.Admin)]
public sealed class LabConnectionsController(LabConnections service) : ControllerBase
{
    [HttpGet] public IActionResult Get() => Ok(service.Configuration());
    [HttpPost("{name}/check")] public async Task<IActionResult> Check(string name, CancellationToken ct) => Ok(await service.Check(name, ct));
}
