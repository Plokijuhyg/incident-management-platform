using System.Net;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Middleware;

/// <summary>
/// Catches any exception that reaches the middleware pipeline and converts it
/// into a consistent RFC 7807 ProblemDetails JSON response. This is the one
/// place that decides "what does an error look like to an API consumer".
///
/// Domain-specific exceptions (NotFoundException, ForbiddenException, etc.)
/// are not handled specially yet — every exception here is treated as an
/// unexpected 500. Mapping specific exception types to specific status codes
/// (404, 409, etc.) is the next step, once we have real domain exceptions
/// to map.
/// </summary>
public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;
    private readonly IHostEnvironment _environment;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger, IHostEnvironment environment)
    {
        _logger = logger;
        _environment = environment;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        // Full exception is always logged server-side, regardless of what we
        // expose to the client. Losing this would make production incidents
        // undebuggable.
        _logger.LogError(
            exception,
            "Unhandled exception on {Method} {Path}",
            httpContext.Request.Method,
            httpContext.Request.Path);

        var problemDetails = new ProblemDetails
        {
            Status = (int)HttpStatusCode.InternalServerError,
            Title = "An unexpected error occurred.",
            Type = "https://tools.ietf.org/html/rfc7231#section-6.6.1",
            Instance = httpContext.Request.Path
        };

        // Detail is the one field that must never leak internals outside
        // Development. The real exception is already captured in the log above.
        problemDetails.Detail = _environment.IsDevelopment()
            ? exception.ToString()
            : "Please contact support if the problem persists.";

        problemDetails.Extensions["timestamp"] = DateTime.UtcNow.ToString("o");
        problemDetails.Extensions["traceId"] = httpContext.TraceIdentifier;

        httpContext.Response.StatusCode = problemDetails.Status.Value;

await httpContext.Response.WriteAsJsonAsync(
    problemDetails,
    options: null,
    contentType: "application/problem+json",
    cancellationToken: cancellationToken);

        return true;
    }
}