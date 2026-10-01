using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Controllers;
[ApiController,Authorize(Roles=$"{RoleNames.Admin},{RoleNames.SecurityManager}"),Route("api/windows-events")]
public sealed class WindowsEventsController(AppDbContext db,WindowsEventCollector collector) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(string? channel=null,int? eventId=null,int? level=null,string? search=null,long? before=null,int limit=100,CancellationToken ct=default)
    {
        limit=Math.Clamp(limit,1,200);
        var q=db.WindowsEvents.AsNoTracking();
        if(!string.IsNullOrWhiteSpace(channel))q=q.Where(x=>x.Channel==channel);
        if(eventId.HasValue)q=q.Where(x=>x.EventId==eventId);
        if(level.HasValue)q=q.Where(x=>x.Level==level);
        if(!string.IsNullOrWhiteSpace(search)) {if(search.Length>200)return BadRequest();q=q.Where(x=>x.Message.Contains(search)||x.Provider.Contains(search)||x.Machine.Contains(search));}
        if(before.HasValue)q=q.Where(x=>x.Id<before);
        var rows=await q.OrderByDescending(x=>x.Id).Take(limit+1).Select(x=>new{x.Id,x.Machine,x.Channel,x.Provider,x.RecordId,x.EventId,x.Level,x.TimeCreated,x.ReceivedAt,x.AlertId}).ToListAsync(ct);
        return Ok(new{items=rows.Take(limit),hasMore=rows.Count>limit});
    }
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Detail(long id,CancellationToken ct) {var row=await db.WindowsEvents.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);return row is null?NotFound():Ok(row);}
    // Counts and minute buckets are aggregated by MySQL, not loaded event entities.
    [HttpGet("activity")]
    public async Task<IActionResult> Activity(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var minute = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, DateTimeKind.Utc);
        var start = minute.AddMinutes(-29);
        var events = db.WindowsEvents.AsNoTracking();
        var recent = events.Where(x => x.ReceivedAt >= start && x.ReceivedAt <= now);
        var buckets = await recent.GroupBy(x => EF.Functions.DateDiffMinute(start, x.ReceivedAt))
            .Select(g => new { Index = g.Key, Count = g.Count() }).ToListAsync(ct);
        var counts = buckets.ToDictionary(x => x.Index, x => x.Count);
        var channels = db.WindowsEventCheckpoints.AsNoTracking().Where(x => x.Enabled);
        return Ok(new {
            observedAt = now, collector.Enabled, collector.LastCycleAt, collector.Error,
            windowsSupported = OperatingSystem.IsWindows(), collector.RetentionDays,
            storedEvents = await events.CountAsync(ct),
            eventsLastMinute = await events.CountAsync(x => x.ReceivedAt >= now.AddMinutes(-1) && x.ReceivedAt <= now, ct),
            lastReceivedAt = await events.MaxAsync(x => (DateTime?)x.ReceivedAt, ct),
            enabledChannels = await channels.CountAsync(ct),
            readableChannels = await channels.CountAsync(x => x.LastCheckedAt != null && x.Error == null, ct),
            blockedChannels = await channels.CountAsync(x => x.Error != null, ct),
            backlogChannels = await channels.CountAsync(x => x.HasBacklog, ct),
            timeline = Enumerable.Range(0, 30).Select(i => new { start = start.AddMinutes(i), count = counts.GetValueOrDefault(i) }),
            topChannels = await recent.GroupBy(x => x.Channel).OrderByDescending(g => g.Count()).ThenBy(g => g.Key)
                .Take(5).Select(g => new { label = g.Key, count = g.Count() }).ToListAsync(ct),
            latest = await events.OrderByDescending(x => x.Id).Take(10)
                .Select(x => new { x.Id, x.Channel, x.Provider, x.EventId, x.Level, x.TimeCreated, x.ReceivedAt, x.AlertId }).ToListAsync(ct)
        });
    }
    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct)=>Ok(new{
        collector.Enabled,collector.PollSeconds,collector.RetentionDays,collector.LastCycleAt,collector.Error,
        machine=Environment.MachineName,windowsSupported=OperatingSystem.IsWindows(),
        storedEvents=await db.WindowsEvents.CountAsync(ct),
        channels=await db.WindowsEventCheckpoints.AsNoTracking().OrderBy(x=>x.Channel).Select(x=>new{x.Id,x.Machine,x.Channel,x.Enabled,x.StartedAt,x.LastCheckedAt,x.LastEventAt,x.Error,x.HasBacklog}).ToListAsync(ct)});
}
