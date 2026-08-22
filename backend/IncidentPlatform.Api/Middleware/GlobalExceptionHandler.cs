using System.Net;
using IncidentPlatform.Api.Exceptions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Middleware;

/// <summary>
/// Catches any exception that reaches the middleware pipeline and converts it
/// into a consistent RFC 7807 ProblemDetails JSON response.
///
/// AppException subtypes (NotFoundException, ConflictException, etc.) are
/// treated as anticipated business outcomes: their own StatusCode is used,
/// and their Message is safe to return to the client as-is (it was written
/// for that purpose).
///
/// Anything else is treated as an unexpected bug: always 500, and the real
/// exception detail is only exposed in Development. This distinction is the
/// whole point of the type — a service should never need to construct a
/// ProblemDetails itself, it just throws the right exception type and this
/// class does the translation, once, in one place.
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
        var problemDetails = exception is AppException appException
            ? BuildKnownProblem(appException, httpContext)
            : BuildUnexpectedProblem(exception, httpContext);

        httpContext.Response.StatusCode = problemDetails.Status!.Value;

        await httpContext.Response.WriteAsJsonAsync(
            problemDetails,
            options: null,
            contentType: "application/problem+json",
            cancellationToken: cancellationToken);

        return true;
    }

    private ProblemDetails BuildKnownProblem(AppException exception, HttpContext httpContext)
    {
        // AppExceptions are expected, routine outcomes (a missing customer,
        // a duplicate email). They're logged at Information, not Error — an
        // error log that fires on every 404 would drown out real problems.
        _logger.LogInformation(
            "{ExceptionType} on {Method} {Path}: {Message}",
            exception.GetType().Name,
            httpContext.Request.Method,
            httpContext.Request.Path,
            exception.Message);

        return new ProblemDetails
        {
            Status = exception.StatusCode,
            Title = exception.Message,
            Type = $"https://tools.ietf.org/html/rfc7231#section-6.{StatusSection(exception.StatusCode)}",
            Instance = httpContext.Request.Path,
            Extensions =
            {
                ["timestamp"] = DateTime.UtcNow.ToString("o"),
                ["traceId"] = httpContext.TraceIdentifier
            }
        };
    }

    private ProblemDetails BuildUnexpectedProblem(Exception exception, HttpContext httpContext)
    {
        // Anything that isn't an AppException is, by definition, a bug we
        // didn't anticipate. Always logged at Error, and the full exception
        // is only ever returned to the client in Development.
        _logger.LogError(
            exception,
            "Unhandled exception on {Method} {Path}",
            httpContext.Request.Method,
            httpContext.Request.Path);

        return new ProblemDetails
        {
            Status = (int)HttpStatusCode.InternalServerError,
            Title = "An unexpected error occurred.",
            Type = "https://tools.ietf.org/html/rfc7231#section-6.6.1",
            Instance = httpContext.Request.Path,
            Detail = _environment.IsDevelopment()
                ? exception.ToString()
                : "Please contact support if the problem persists.",
            Extensions =
            {
                ["timestamp"] = DateTime.UtcNow.ToString("o"),
                ["traceId"] = httpContext.TraceIdentifier
            }
        };
    }

    // Maps a status code to its RFC 7231 section number, purely for the
    // ProblemDetails "Type" URI. Falls back to the generic section if a
    // status code isn't one of the ones we currently throw.
    private static string StatusSection(int statusCode) => statusCode switch
    {
        400 => "5.1",
        403 => "5.3",
        404 => "5.4",
        409 => "5.8",
        _ => "6.1"
    };
}
