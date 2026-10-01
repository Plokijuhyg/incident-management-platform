using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;

namespace IncidentPlatform.Api.Services;

public sealed class WindowsEventCollector(IServiceScopeFactory scopes, IConfiguration config, IHostEnvironment environment,
    ILogger<WindowsEventCollector> logger) : BackgroundService
{
    public bool Enabled => config.GetValue<bool>("WindowsEvents:Enabled") && !environment.IsEnvironment("Testing");
    public DateTime? LastCycleAt { get; private set; }
    public string? Error { get; private set; }
    public int PollSeconds => Math.Clamp(config.GetValue("WindowsEvents:PollSeconds", 2), 2, 60);
    public int RetentionDays => Math.Clamp(config.GetValue("WindowsEvents:RetentionDays", 7), 1, 365);
    private DateTime discoveryAt;
    private DateTime retentionAt;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!Enabled) return;
        if (!OperatingSystem.IsWindows()) { Error="The local collector requires Windows."; return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try { Error=null; await Collect(stoppingToken); if(Error is null)LastCycleAt=DateTime.UtcNow; }
            catch (OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
            catch (Exception e) { Error="Collection paused: check database availability and server logs."; logger.LogError(e,"Windows event collection cycle failed; checkpoints retained"); }
            try { await Task.Delay(TimeSpan.FromSeconds(PollSeconds),stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
    [SupportedOSPlatform("windows")]
    private async Task Collect(CancellationToken ct)
    {
        using var scope=scopes.CreateScope();
        var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        var connection=(MySqlConnection)db.Database.GetDbConnection();
        // One writer per database, even when two development API processes are started.
        var lockName="win-events:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(connection.Database)))[..40];
        await using var guard=new MySqlCommand("SELECT GET_LOCK(@name,0)",connection);guard.Parameters.AddWithValue("@name",lockName);
        if(Convert.ToInt32(await guard.ExecuteScalarAsync(ct))!=1) { Error="Another API instance owns the collector.";return; }
        try
        {
            var machine=Environment.MachineName;
            var channels=await db.WindowsEventCheckpoints.Where(x=>x.Machine==machine).ToListAsync(ct);
            if(discoveryAt<DateTime.UtcNow.AddMinutes(-5))
            {
                using var session=new EventLogSession();
                var names=session.GetLogNames().Append("Security").Distinct().ToList();
                foreach(var name in names)
                {
                    var row=channels.SingleOrDefault(x=>x.Channel==name);
                    if(row is null) {row=new(){Machine=machine,Channel=name,StartedAt=DateTime.UtcNow.AddMinutes(-Math.Clamp(config.GetValue("WindowsEvents:InitialLookbackMinutes",5),0,1440))};channels.Add(row);db.Add(row);}
                    try { using var settings=new EventLogConfiguration(name);row.Enabled=settings.IsEnabled;if(!row.Enabled)row.Error="Channel disabled in Windows; not collected."; }
                    catch(Exception e) when(e is EventLogException or UnauthorizedAccessException or System.Security.SecurityException) { row.Enabled=true;row.Error="Channel configuration unavailable; attempting read."; }
                }
                await db.SaveChangesAsync(ct);discoveryAt=DateTime.UtcNow;
            }
            foreach(var row in channels.Where(x=>x.Enabled))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var start=row.StartedAt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ",CultureInfo.InvariantCulture);
                    var query=new EventLogQuery(row.Channel,PathType.LogName,$"*[System[TimeCreated[@SystemTime >= '{start}']]]");
                    using var reader=row.Bookmark is null ? new EventLogReader(query) : new EventLogReader(query,new EventBookmark(row.Bookmark));
                    var events=new List<WindowsEvent>();string? bookmark=null;
                    for(var n=0;n<100;n++)
                    {
                        ct.ThrowIfCancellationRequested();using var record=reader.ReadEvent(TimeSpan.FromSeconds(2));if(record is null)break;
                        var xml=record.ToXml();string message;
                        try {message=record.FormatDescription()??"Message resource unavailable; inspect original XML.";}catch(EventLogException){message="Message resource unavailable; inspect original XML.";}
                        events.Add(new(){Machine=machine,Channel=row.Channel,Provider=record.ProviderName??"Unknown",RecordId=record.RecordId,EventId=record.Id,
                            Level=record.Level??0,TimeCreated=record.TimeCreated?.ToUniversalTime(),ReceivedAt=DateTime.UtcNow,Message=message,RawXml=xml,
                            Fingerprint=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machine+"\n"+row.Channel+"\n"+xml)))});
                        bookmark=record.Bookmark.BookmarkXml;
                    }
                    // Persist rows, rule alerts and cursor atomically; failed commits are replayed.
                    await using var transaction=await db.Database.BeginTransactionAsync(ct);
                    await WindowsEventWriter.Store(db,events,"127.0.0.1",ct);
                    if(bookmark is not null)row.Bookmark=bookmark;
                    if(events.Count>0)row.LastEventAt=events.Last().TimeCreated;
                    row.LastCheckedAt=DateTime.UtcNow;row.HasBacklog=events.Count==100;row.Error=null;
                    await db.SaveChangesAsync(ct);await transaction.CommitAsync(ct);
                    // Avoid tracking every stored event for the lifetime of a channel sweep.
                    foreach(var entry in db.ChangeTracker.Entries().Where(x=>x.Entity is WindowsEvent or Alert or AuditLog).ToList())entry.State=EntityState.Detached;
                }
                catch(Exception e) when(e is EventLogException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    row.LastCheckedAt=DateTime.UtcNow;
                    if(row.Error is null)logger.LogWarning(e,"Cannot collect Windows channel {Channel}",row.Channel);
                    row.Error=e is UnauthorizedAccessException or System.Security.SecurityException ? "Access denied. Grant this process Event Log Readers access or run the local backend elevated." : "Windows could not read this channel or resume its bookmark. Check channel permissions/availability; a cleared log may require an explicit cursor reset. " + e.Message[..Math.Min(e.Message.Length,300)];
                    row.HasBacklog=false;
                    await db.SaveChangesAsync(ct);
                }
            }
            if(retentionAt<DateTime.UtcNow.AddHours(-1))
            {
                var cutoff=DateTime.UtcNow.AddDays(-RetentionDays);
                await db.WindowsEvents.Where(x=>x.ReceivedAt<cutoff).ExecuteDeleteAsync(ct);retentionAt=DateTime.UtcNow;
            }
        }
        finally {await using var release=new MySqlCommand("SELECT RELEASE_LOCK(@name)",connection);release.Parameters.AddWithValue("@name",lockName);await release.ExecuteScalarAsync(CancellationToken.None);}
    }
}
