using System.Net;

namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Maps to 401. Deliberately carries one fixed, generic message regardless
/// of the actual cause (unknown email, wrong password, locked account,
/// deactivated account) — api-design.md §2: distinguishing these is a
/// user-enumeration oracle. Callers never pass a custom message to this
/// exception for that reason; the constructor takes none.
/// </summary>
public sealed class AuthenticationFailedException : AppException
{
    public override int StatusCode => (int)HttpStatusCode.Unauthorized;

    public AuthenticationFailedException() : base("Invalid email or password.")
    {
    }
}
