using System.Security.Claims;
using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace IncidentPlatform.Api.Middleware;

// Outside the exception handler and authorization: observes their final failure status.
public sealed class AuditMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IAuditContext audit)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            if (int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
                audit.ActorUserId = id;
            audit.ActorEmail = context.User.FindFirstValue(ClaimTypes.Email);
        }

        var endpoint = context.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>();
        var entityId = (context.Request.RouteValues["evidenceId"] ?? context.Request.RouteValues["id"] ??
            context.Request.RouteValues["incidentId"])?.ToString();
        await next(context);
        if (!context.Request.Path.StartsWithSegments("/api") || context.Response.StatusCode < 400)
            return;

        if (audit.ActorUserId is null && context.Items.TryGetValue(LoginIdentityMiddleware.EmailKey, out var email))
            audit.ActorEmail = email as string;

        // A failed service may leave pending writes in its DbContext. Never save those.
        using var scope = context.RequestServices.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var action = endpoint?.ControllerName == "Auth" && endpoint.ActionName == "Login"
            ? "LOGIN_FAILED" : context.Response.StatusCode is 401 or 403 ? "ACCESS_DENIED" : "REQUEST_FAILED";
        db.AuditLogs.Add(audit.Create(action, endpoint?.ControllerName,
            entityId,
            action == "LOGIN_FAILED" ? AuditOutcome.Failure :
                context.Response.StatusCode is 401 or 403 ? AuditOutcome.Denied : AuditOutcome.Failure,
            JsonSerializer.Serialize(new { method = context.Request.Method,
                endpoint = endpoint?.ActionName, statusCode = context.Response.StatusCode, traceId = context.TraceIdentifier })));
        // Persist even if the caller disconnected. No cookies, tokens, bodies or query strings.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await db.SaveChangesAsync(timeout.Token);
    }
}
