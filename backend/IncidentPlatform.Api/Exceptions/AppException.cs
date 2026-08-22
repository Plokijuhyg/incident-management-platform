namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Base type for all exceptions that represent an anticipated business
/// outcome (not found, conflict, forbidden, etc.) rather than a genuine bug.
/// GlobalExceptionHandler checks for this type first; anything that isn't an
/// AppException is treated as an unexpected 500, per the design already in
/// place.
/// </summary>
public abstract class AppException : Exception
{
    public abstract int StatusCode { get; }

    protected AppException(string message) : base(message)
    {
    }
}
