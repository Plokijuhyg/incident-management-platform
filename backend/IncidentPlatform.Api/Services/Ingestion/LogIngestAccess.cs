using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IncidentPlatform.Api.Services.Ingestion;

/// <summary>
/// Gate for the anonymous log-ingestion endpoint. A log forwarder (syslog relay,
/// firewall, VPN concentrator) cannot carry a JWT, so it authenticates with a
/// pre-shared key sent as <c>X-Ingest-Key</c>, compared in constant time against
/// the SHA-256 hashes in configuration. Mirrors the telemetry gate:
/// disabled → 503, non-HTTPS → 400, bad key → 401, every rejection audited.
/// </summary>
public sealed class LogIngestAccess(IConfiguration config, AppDbContext db) : IAsyncResourceFilter
{
    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        var http = context.HttpContext;
        string? reason = null;
        var status = 401;

        if (!config.GetValue<bool>("Ingestion:Enabled")) { reason = "IngestionDisabled"; status = 503; }
        else if (!http.Request.IsHttps) { reason = "HttpsRequired"; status = 400; }
        else
        {
            var key = http.Request.Headers["X-Ingest-Key"].ToString();
            var configured = config.GetSection("Ingestion:Keys").Get<string[]>() ?? [];
            if (key.Length is < 16 or > 256 || !Matches(key, configured)) reason = "InvalidIngestKey";
        }

        if (reason is not null)
        {
            db.AuditLogs.Add(new AuditLog
            {
                Action = "LOG_INGEST_REJECTED", EntityType = "LogSource", Outcome = AuditOutcome.Denied,
                IpAddress = http.Connection.RemoteIpAddress?.ToString() ?? "unknown", OccurredAt = DateTime.UtcNow,
                Details = JsonSerializer.Serialize(new { reason, traceId = http.TraceIdentifier }),
            });
            await db.SaveChangesAsync(http.RequestAborted);
            context.Result = new ObjectResult(new { error = "Log ingestion request rejected", traceId = http.TraceIdentifier }) { StatusCode = status };
            return;
        }
        await next();
    }

    private static bool Matches(string key, string[] configuredHashes)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        foreach (var configured in configuredHashes)
        {
            if (configured.Length != 64) continue;
            try
            {
                if (CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(configured))) return true;
            }
            catch (FormatException) { /* skip a malformed configured hash */ }
        }
        return false;
    }
}
