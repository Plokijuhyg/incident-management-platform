using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
namespace IncidentPlatform.Api.Services;
public sealed record TelemetryAgent(string Id,string TargetId,string TokenSha256,bool Enabled);
public sealed record TelemetryIdentity(TelemetryAgent Agent,ApprovedAssessmentTarget Target);
public sealed class TelemetryAccess(IConfiguration config,ApprovedLabTargets targets,AppDbContext db) : IAsyncResourceFilter
{
    public const string IdentityKey="VerifiedTelemetryIdentity";
    public async Task OnResourceExecutionAsync(ResourceExecutingContext context,ResourceExecutionDelegate next)
    {
        var http=context.HttpContext;
        var id=http.Request.Headers["X-Agent-Id"].ToString();
        var token=http.Request.Headers["X-Telemetry-Token"].ToString();
        string? reason=null;
        var status=403;
        TelemetryAgent? agent=null;ApprovedAssessmentTarget? target=null;
        if(!config.GetValue<bool>("Telemetry:Enabled")){reason="TelemetryDisabled";status=503;}
        else if(!http.Request.IsHttps){reason="HttpsRequired";status=400;}
        else
        {
            agent=(config.GetSection("Telemetry:Agents").Get<TelemetryAgent[]>()??[]).FirstOrDefault(a=>a.Enabled && a.Id==id);
            if(agent is null || agent.Id.Length>50 || token.Length is <32 or >256 || !ValidToken(token,agent.TokenSha256)){reason="InvalidAgentCredentials";status=401;}
            else
            {
                target=targets.Find(agent.TargetId);
                if(target is null || string.IsNullOrWhiteSpace(target.Hostname) || !ApprovedLabTargets.SameAddress(target.Ip,http.Connection.RemoteIpAddress))reason="UnapprovedSource";
            }
        }
        if(reason is not null)
        {
            await Denied(db,http,id,reason);
            context.Result=new ObjectResult(new{error="Telemetry request rejected",traceId=http.TraceIdentifier}){StatusCode=status};return;
        }
        http.Items[IdentityKey]=new TelemetryIdentity(agent!,target!);
        await next();
    }
    public static bool ValidToken(string token,string? hash)
    {
        if(hash is null || hash.Length!=64)return false;
        try{return CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)),Convert.FromHexString(hash));}
        catch(FormatException){return false;}
    }
    public static async Task Denied(AppDbContext db,HttpContext http,string id,string reason,string action="TELEMETRY_REJECTED",string entityType="TelemetryAgent")
    {
        db.AuditLogs.Add(new(){Action=action,EntityType=entityType,EntityId=id[..Math.Min(id.Length,50)],Outcome=AuditOutcome.Denied,IpAddress=http.Connection.RemoteIpAddress?.ToString()??"unknown",OccurredAt=DateTime.UtcNow,Details=JsonSerializer.Serialize(new{reason,traceId=http.TraceIdentifier})});
        await db.SaveChangesAsync(http.RequestAborted);
    }
}
