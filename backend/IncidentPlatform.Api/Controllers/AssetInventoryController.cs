using System.Runtime.InteropServices;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
[ApiController,Route("api/assets"),Authorize(Roles=RoleNames.Admin)]
public sealed class AssetInventoryController(AppDbContext db,IConfiguration config):ControllerBase
{
    [HttpPost("sync-sources")]
    public async Task<IActionResult> Sync(CancellationToken ct)
    {
        // Inventory only: never grants telemetry approval or scans an asset.
        var names=await db.WindowsEvents.Select(e=>e.Machine).Distinct().ToListAsync(ct);
        var targets=new ApprovedLabTargets(config).All.Where(t=>t.Approved && AssessmentGateway.PrivateIp(t.Ip)).ToArray();
        var existing=await db.Assets.ToListAsync(ct);var added=0;
        foreach(var machine in names)
        {
            if(existing.Any(a=>string.Equals(a.Hostname,machine,StringComparison.OrdinalIgnoreCase)||string.Equals(a.Name,machine,StringComparison.OrdinalIgnoreCase)))continue;
            var a=new Asset{Name=machine,Hostname=machine,Type=AssetType.Workstation,Criticality=AssetCriticality.Medium,OperatingSystem=machine.Equals(Environment.MachineName,StringComparison.OrdinalIgnoreCase)?RuntimeInformation.OSDescription:null,Location="Observed Windows log source",CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow};
            db.Assets.Add(a);existing.Add(a);added++;
        }
        foreach(var target in targets)
        {
            if(existing.Any(a=>a.IpAddress==target.Ip || target.Hostname!=null && string.Equals(a.Hostname,target.Hostname,StringComparison.OrdinalIgnoreCase)))continue;
            var a=new Asset{Name=target.Name,Hostname=target.Hostname,IpAddress=target.Ip,Type=AssetType.Server,Criticality=AssetCriticality.Low,Location="Approved laboratory target",CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow};db.Assets.Add(a);existing.Add(a);added++;
        }
        await db.SaveChangesAsync(ct);return Ok(new{added,message="Inventory synchronized from validated event sources and approved lab targets. Log collection approval is unchanged."});
    }
}
