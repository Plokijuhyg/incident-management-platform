using System.Net;

namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Thrown when a request conflicts with the current state of a resource.
/// Maps to 409. Example: creating a user with an email that already exists,
/// or (later) creating an invoice line item that exceeds available stock.
/// </summary>
public sealed class ConflictException : AppException
{
    public override int StatusCode => (int)HttpStatusCode.Conflict;

    public ConflictException(string message) : base(message)
    {
    }
}
