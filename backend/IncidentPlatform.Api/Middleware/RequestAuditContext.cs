using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Middleware;

public sealed class RequestAuditContext(IHttpContextAccessor accessor) : IAuditContext
{
    public bool IsActive => accessor.HttpContext is not null;
    public int? ActorUserId { get; set; }
    public string? ActorEmail { get; set; }

    public AuditLog Create(string action, string? entityType = null, string? entityId = null,
        AuditOutcome outcome = AuditOutcome.Success, string? details = null) => new()
    {
        ActorUserId = ActorUserId,
        ActorEmail = Clip(ActorEmail, 256),
        Action = action,
        EntityType = entityType,
        EntityId = entityId,
        Outcome = outcome,
        IpAddress = Clip(accessor.HttpContext?.Connection.RemoteIpAddress?.ToString(), 45) ?? "unknown",
        UserAgent = Clip(accessor.HttpContext?.Request.Headers.UserAgent.ToString(), 500),
        Details = details,
        OccurredAt = DateTime.UtcNow
    };

    private static string? Clip(string? value, int length) => value is { Length: > 0 }
        ? value[..Math.Min(value.Length, length)] : null;
}
