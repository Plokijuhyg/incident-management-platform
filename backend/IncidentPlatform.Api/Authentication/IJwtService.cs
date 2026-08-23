using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Authentication;

public interface IJwtService
{
    /// <summary>
    /// Generates a signed access token for the given user and their current
    /// role names. Roles are passed explicitly rather than loaded from
    /// user.UserRoles inside this service, so the service has no dependency
    /// on AppDbContext or navigation-property loading state.
    /// </summary>
    string GenerateAccessToken(User user, IReadOnlyList<string> roleNames);
}
