using IncidentPlatform.Api.Middleware;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------
builder.Services.AddControllers();

// OpenAPI document generation. Exposed in non-Production only (see below).
builder.Services.AddOpenApi();

// Liveness only at this stage. A MySQL readiness check is added in Phase 4,
// per docs/api-design.md §10.
builder.Services.AddHealthChecks();

// Enables ProblemDetails for framework-generated responses too (model
// validation 400s, 404 on unmatched routes), not just our own thrown
// exceptions — so the error shape is consistent everywhere, not just where
// GlobalExceptionHandler runs.
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var app = builder.Build();

// ---------------------------------------------------------------------------
// HTTP pipeline
//
// The full middleware order is specified in docs/architecture.md §4 and is
// built up phase by phase. Exception handling goes first so it can catch
// anything thrown by everything after it. Not yet wired: request logging,
// security headers, CORS, rate limiting, authentication and authorization.
// ---------------------------------------------------------------------------
app.UseExceptionHandler();

if (!app.Environment.IsProduction())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapControllers();

// Anonymous liveness probe. Deliberately returns no dependency detail — a
// health endpoint that enumerates infrastructure is reconnaissance.
app.MapHealthChecks("/health");

app.Run();

// Exposed so integration tests can host the application through
// WebApplicationFactory<Program>. Top-level statements otherwise generate an
// internal Program class that the test project cannot reference.
public partial class Program;
