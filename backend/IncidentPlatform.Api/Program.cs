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

var app = builder.Build();

// ---------------------------------------------------------------------------
// HTTP pipeline
//
// The full middleware order is specified in docs/architecture.md §4 and is
// built up phase by phase. Not yet wired: global exception handling, request
// logging, security headers, CORS, rate limiting, authentication and
// authorization. Order matters for correctness, so each is inserted at its
// designated position rather than appended.
// ---------------------------------------------------------------------------
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
