using System.Net;

namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Thrown when an authenticated user is not permitted to perform an action
/// on a specific resource — an authorization failure at the business-rule
/// level, not the role level. Maps to 403.
///
/// Distinct from ASP.NET Core's [Authorize(Roles = "...")], which handles
/// coarse role checks before a request even reaches a controller action.
/// This exception is for finer-grained checks a role attribute can't express
/// — for example, "a SOC Analyst can only resolve incidents assigned to
/// them", which depends on the specific incident, not just the caller's role.
/// </summary>
public sealed class ForbiddenException : AppException
{
    public override int StatusCode => (int)HttpStatusCode.Forbidden;

    public ForbiddenException(string message) : base(message)
    {
    }
}
