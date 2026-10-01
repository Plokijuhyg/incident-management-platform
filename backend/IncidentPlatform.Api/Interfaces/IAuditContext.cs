using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Interfaces;

public interface IAuditContext
{
    bool IsActive { get; }
    int? ActorUserId { get; set; }
    string? ActorEmail { get; set; }
    AuditLog Create(string action, string? entityType = null, string? entityId = null,
        AuditOutcome outcome = AuditOutcome.Success, string? details = null);
}
