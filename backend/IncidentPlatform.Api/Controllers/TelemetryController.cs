using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;
namespace IncidentPlatform.Api.Controllers;
public sealed record TelemetryEvent([property:Required,StringLength(65536)]string RawXml,[property:StringLength(8192)]string? Message);
public sealed record TelemetryBatch(Guid BatchId,[property:Required,MinLength(1),MaxLength(64)]TelemetryEvent[] Events);
[ApiController,AllowAnonymous,Route("api/telemetry/events"),ServiceFilter(typeof(TelemetryAccess))]
public sealed class TelemetryController(AppDbContext db):ControllerBase
{
    [HttpPost,RequestSizeLimit(2*1024*1024)]
    public async Task<IActionResult> Ingest(TelemetryBatch batch,CancellationToken ct)
    {
        var identity=(TelemetryIdentity)HttpContext.Items[TelemetryAccess.IdentityKey]!;
        List<WindowsEvent> events;
        try
        {
            if(batch.BatchId==Guid.Empty)throw new FormatException();
            events=batch.Events.Select(e=>Parse(e,identity.Target.Hostname!)).ToList();
        }
        catch(Exception e) when(e is XmlException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            await TelemetryAccess.Denied(db,HttpContext,identity.Agent.Id,"InvalidEventOrMachine");
            return BadRequest(new{error="Invalid Windows event batch; no events accepted"});
        }
        await db.Database.OpenConnectionAsync(ct);
        var connection=(MySqlConnection)db.Database.GetDbConnection();
        var name="win-events:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(connection.Database)))[..40];
        await using var guard=new MySqlCommand("SELECT GET_LOCK(@name,5)",connection);guard.Parameters.AddWithValue("@name",name);
        if(Convert.ToInt32(await guard.ExecuteScalarAsync(ct))!=1){Response.Headers.RetryAfter="5";return StatusCode(503,new{error="Collector busy; retry the same batch"});}
        try
        {
            await using var tx=await db.Database.BeginTransactionAsync(ct);
            var added=await WindowsEventWriter.Store(db,events,HttpContext.Connection.RemoteIpAddress!.ToString(),ct);
            db.AuditLogs.Add(new(){Action="TELEMETRY_BATCH_ACCEPTED",EntityType="TelemetryAgent",EntityId=identity.Agent.Id,Outcome=AuditOutcome.Success,IpAddress=HttpContext.Connection.RemoteIpAddress!.ToString(),OccurredAt=DateTime.UtcNow,Details=JsonSerializer.Serialize(new{batch.BatchId,targetId=identity.Target.Id,machine=identity.Target.Hostname,accepted=added,duplicates=events.Count-added})});
            await db.SaveChangesAsync(ct);await tx.CommitAsync(ct);
            return Ok(new{batchId=batch.BatchId,accepted=added,duplicates=events.Count-added});
        }
        finally
        {
            await using var release=new MySqlCommand("SELECT RELEASE_LOCK(@name)",connection);release.Parameters.AddWithValue("@name",name);await release.ExecuteScalarAsync(CancellationToken.None);
        }
    }
    public static WindowsEvent Parse(TelemetryEvent item,string expectedMachine)
    {
        if(item is null || string.IsNullOrWhiteSpace(item.RawXml))throw new FormatException();
        using var reader=XmlReader.Create(new StringReader(item.RawXml),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=65536});
        var doc=XDocument.Load(reader);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        if(doc.Root?.Name!=ns+"Event")throw new FormatException();
        var system=doc.Root.Element(ns+"System")??throw new FormatException();
        string Required(string name)=>system.Element(ns+name)?.Value??throw new FormatException();
        var machine=ApprovedLabTargets.Machine(Required("Computer"));
        if(machine!=ApprovedLabTargets.Machine(expectedMachine) || machine.Length>255)throw new FormatException();
        var channel=Required("Channel");var provider=(string?)system.Element(ns+"Provider")?.Attribute("Name")??throw new FormatException();
        if(channel.Length is <1 or >255 || provider.Length is <1 or >255)throw new FormatException();
        var eventId=int.Parse(Required("EventID"),CultureInfo.InvariantCulture);
        var level=int.Parse(Required("Level"),CultureInfo.InvariantCulture);
        var record=long.Parse(Required("EventRecordID"),CultureInfo.InvariantCulture);
        var time=DateTimeOffset.Parse((string?)system.Element(ns+"TimeCreated")?.Attribute("SystemTime")??throw new FormatException(),CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal).UtcDateTime;
        if(eventId is <0 or >65535 || level is <0 or >5 || record<0 || time>DateTime.UtcNow.AddMinutes(5))throw new FormatException();
        return new(){Machine=machine,Channel=channel,Provider=provider,EventId=eventId,Level=level,RecordId=record,TimeCreated=time,ReceivedAt=DateTime.UtcNow,RawXml=item.RawXml,Message=item.Message??"Inspect original XML.",Fingerprint=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(machine+"\n"+channel+"\n"+item.RawXml)))};
    }
}
