using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using IncidentPlatform.Api.Middleware;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace IncidentPlatform.Api.Configuration;

public static class ApiRateLimiting
{
    public static IServiceCollection AddApiRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(Partition);
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (rejected, ct) =>
            {
                if(rejected.HttpContext.Request.Path == "/api/telemetry/events")
                    await IncidentPlatform.Api.Services.TelemetryAccess.Denied(rejected.HttpContext.RequestServices.GetRequiredService<IncidentPlatform.Api.Data.AppDbContext>(),rejected.HttpContext,"", "RateLimited");
                var seconds = rejected.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retry)
                    ? Math.Max(1, (int)Math.Ceiling(retry.TotalSeconds)) : 60;
                rejected.HttpContext.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
                await Results.Problem(statusCode: 429, title: "Too many requests.",
                    extensions: new Dictionary<string, object?> { ["traceId"] = rejected.HttpContext.TraceIdentifier })
                    .ExecuteAsync(rejected.HttpContext);
            };
        });
        return services;
    }

    public static RateLimitPartition<string> Partition(HttpContext context)
    {
        var endpoint = context.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>();
        var identity = context.User.Identity?.IsAuthenticated == true
            ? "user:" + context.User.FindFirstValue(ClaimTypes.NameIdentifier)
            : "ip:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        var policy = "global";
        var limit = 300;
        var window = TimeSpan.FromMinutes(1);
        if (endpoint is { ControllerName: "Auth", ActionName: "Login" })
        {
            policy = "login";
            limit = 5;
            window = TimeSpan.FromMinutes(15);
            var email = context.Items[LoginIdentityMiddleware.EmailKey] as string ?? "";
            identity = (context.Connection.RemoteIpAddress?.ToString() ?? "unknown") + ":" +
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(email)));
        }
        else if (endpoint is { ControllerName: "AssessmentAnalysis", ActionName: "Analyze" })
        { policy="assessment-analysis"; limit=6; }
        else if (endpoint is { ControllerName: "Telemetry" })
        {
            policy="telemetry"; limit=120; identity="ip:"+(context.Connection.RemoteIpAddress?.ToString()??"unknown");
        }
        else if (endpoint is { ControllerName: "Evidence", ActionName: "Upload" })
        {
            policy = "upload";
            limit = 20;
            window = TimeSpan.FromHours(1);
        }
        else if (HttpMethods.IsGet(context.Request.Method) && context.Request.Query.ContainsKey("search"))
        {
            policy = "search";
            limit = 60;
        }
        return RateLimitPartition.GetFixedWindowLimiter(policy + ":" + identity, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = limit, Window = window, QueueLimit = 0, AutoReplenishment = true
        });
    }
}
