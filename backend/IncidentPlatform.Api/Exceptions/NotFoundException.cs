using System.Net;

namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Thrown when a requested entity does not exist. Maps to 404.
/// Example: GetIncidentById(999) when incident 999 was never created.
/// </summary>
public sealed class NotFoundException : AppException
{
    public override int StatusCode => (int)HttpStatusCode.NotFound;

    public NotFoundException(string message) : base(message)
    {
    }

    /// <summary>
    /// Convenience constructor for the common "Entity with id X not found" case.
    /// </summary>
    public NotFoundException(string entityName, object id)
        : base($"{entityName} with id '{id}' was not found.")
    {
    }
}
