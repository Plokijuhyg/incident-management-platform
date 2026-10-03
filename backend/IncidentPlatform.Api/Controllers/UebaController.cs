using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Controllers;

[ApiController, Route("api/ueba"), Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager}")]
public sealed class UebaController(AppDbContext db) : ControllerBase
{
    // Riskiest entities first, so an analyst sees who to look at.
    [HttpGet("entities")]
    public async Task<IActionResult> Entities([FromQuery] string? type = null, [FromQuery] int limit = 50, CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        var query = db.EntityProfiles.AsNoTracking();
        if (type is "user" or "host") query = query.Where(p => p.EntityType == type);
        var rows = await query
            .OrderByDescending(p => p.RiskScore).ThenByDescending(p => p.LastAnomalyAt).ThenByDescending(p => p.LastSeenAt)
            .Take(limit)
            .Select(p => new
            {
                p.Id, p.EntityType, p.EntityValue, p.RiskScore, p.FailedLoginsHour, p.EventCount,
                p.LastAnomaly, p.LastAnomalyAt, p.FirstSeenAt, p.LastSeenAt
            })
            .ToListAsync(ct);
        return Ok(new
        {
            total = await db.EntityProfiles.CountAsync(ct),
            withAnomalies = await db.EntityProfiles.CountAsync(p => p.RiskScore > 0, ct),
            items = rows
        });
    }

    [HttpGet("entities/{id:long}")]
    public async Task<IActionResult> Entity(long id, CancellationToken ct)
    {
        var p = await db.EntityProfiles.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (p is null) return NotFound();
        var ips = Ips(p.KnownSourceIpsJson);
        var alerts = await db.Alerts.AsNoTracking()
            .Where(a => a.Source == AlertSource.Ueba &&
                (p.EntityType == "user" ? a.Username == p.EntityValue : a.Host == p.EntityValue))
            .OrderByDescending(a => a.Id).Take(25)
            .Select(a => new { a.Id, a.Title, a.Severity, a.Status, a.IncidentId, a.DetectedAt })
            .ToListAsync(ct);
        return Ok(new
        {
            p.Id, p.EntityType, p.EntityValue, p.RiskScore, p.FailedLoginsHour, p.EventCount,
            p.LastAnomaly, p.LastAnomalyAt, p.FirstSeenAt, p.LastSeenAt,
            knownSourceIps = ips, knownSourceIpCount = ips.Count, recentAlerts = alerts
        });
    }

    private static List<string> Ips(string json)
    {
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch (JsonException) { return []; }
    }
}
