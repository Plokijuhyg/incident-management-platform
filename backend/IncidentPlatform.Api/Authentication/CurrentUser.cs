using System.Security.Claims;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;

namespace IncidentPlatform.Api.Authentication;

public class CurrentUser : ICurrentUser
{
    public int Id { get; }
    public IReadOnlyList<string> Roles { get; }

    public CurrentUser(IHttpContextAccessor httpContextAccessor)
    {
        var user = httpContextAccessor.HttpContext?.User
            ?? throw new AuthenticationFailedException();

        var idClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (idClaim is null || !int.TryParse(idClaim, out var id))
        {
            throw new AuthenticationFailedException();
        }

        Id = id;
        Roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
    }

    public bool IsInRole(string role) => Roles.Contains(role);
}
