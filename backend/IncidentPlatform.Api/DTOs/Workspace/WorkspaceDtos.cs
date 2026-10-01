using IncidentPlatform.Api.Models;
namespace IncidentPlatform.Api.DTOs.Workspace;

public record AuditEntry(long Id, int? ActorUserId, string? ActorEmail, string Action, string? EntityType, string? EntityId, AuditOutcome Outcome, string IpAddress, string? Details, DateTime OccurredAt);
public record IncidentLink(int Id, string Name, string? Reference, int? Classification, string? Notes, DateTime AddedAt);
public record LabConfiguration(string HexStrikeUrl, string OllamaUrl);
public record ConnectionResult(string Service, string Url, bool Reachable, string Message, DateTime CheckedAt);
