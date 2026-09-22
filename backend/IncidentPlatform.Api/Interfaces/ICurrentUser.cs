namespace IncidentPlatform.Api.Interfaces;

/// <summary>
/// Per architecture.md §2: services never see HttpContext/ClaimsPrincipal
/// directly. This is the one abstraction that carries the caller's identity
/// into the service layer, so services stay unit-testable without a web host.
/// </summary>
public interface ICurrentUser
{
    int Id { get; }
    IReadOnlyList<string> Roles { get; }
    bool IsInRole(string role);
}