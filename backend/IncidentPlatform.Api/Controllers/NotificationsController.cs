using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
[ApiController,Route("api/notifications"),Authorize(Roles=RoleNames.Admin)]
public sealed class NotificationsController(AppDbContext db,IConfiguration config):ControllerBase
{
 [HttpGet("status")]public async Task<IActionResult> Status(CancellationToken ct){var s=NotificationSettings.Read(config);return Ok(new{s.Enabled,configured=s.Missing.Length==0,s.Missing,minimumSeverity=s.Threshold.ToString(),counts=await db.IncidentNotifications.GroupBy(n=>n.State).Select(g=>new{state=g.Key,count=g.Count()}).ToListAsync(ct)});}
}
