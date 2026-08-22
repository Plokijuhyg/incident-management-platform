using IncidentPlatform.Api.Middleware;
using Serilog;
using Serilog.Formatting.Compact;
using Microsoft.Extensions.Hosting;
using IncidentPlatform.Api.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

// Configured before WebApplication.CreateBuilder so that any startup failure
// (e.g. a bad connection string, added in Phase 4) is itself captured by
// Serilog instead of being lost to an unhandled exception before logging
// exists.
Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithThreadId()
    .WriteTo.Console()
    .WriteTo.File(
        new CompactJsonFormatter(),
        path: "logs/log-.json",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14)
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting IncidentPlatform.Api");

    var builder = WebApplication.CreateBuilder(args);

    // Replaces the default console logger with Serilog for the whole host.
    // Reads the final configuration from appsettings.json's "Serilog"
    // section, layered on top of the bootstrap logger above.
      builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithMachineName()
        .Enrich.WithThreadId()
        .WriteTo.Console()
        .WriteTo.File(
            new CompactJsonFormatter(),
            path: "logs/log-.json",
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 14));

    // -----------------------------------------------------------------------
    // Services
    // -----------------------------------------------------------------------
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
        // Strongly-typed, validated configuration. ValidateDataAnnotations()
    // checks the [Required]/[MinLength] attributes on CorsSettings;
    // ValidateOnStart() means a bad config fails the app immediately at
    // startup, not the first time something tries to read the setting.
    builder.Services
        .AddOptions<CorsSettings>()
        .Bind(builder.Configuration.GetSection(CorsSettings.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

        // CORS policy itself. The allowed origins list is read from CorsSettings
    // via IOptions at the time this policy is built — Program.cs never reads
    // configuration strings directly, keeping the single source of truth in
    // CorsSettings.
    builder.Services.AddCors(corsOptions =>
    {
        corsOptions.AddPolicy("AngularApp", policy =>
        {
            using var serviceProvider = builder.Services.BuildServiceProvider();
            var corsSettings = serviceProvider.GetRequiredService<IOptions<CorsSettings>>().Value;

            policy
                .WithOrigins(corsSettings.AllowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });

    var app = builder.Build();

    // -------------------------------------------------------------------------
    // HTTP pipeline
    //
    // The full middleware order is specified in docs/architecture.md §4 and is
    // built up phase by phase. Exception handling goes first so it can catch
    // anything thrown by everything after it. Request logging goes right after,
    // so it captures the final status code even when the exception handler
    // changed it. Not yet wired: security headers, CORS, rate limiting,
    // authentication and authorization.
    // -------------------------------------------------------------------------
    app.UseExceptionHandler();

    // One structured log line per request: method, path, status code, elapsed
    // ms. This is the "what happened" log; GlobalExceptionHandler's own logs
    // are the "what went wrong" detail for the subset of requests that failed.
    app.UseSerilogRequestLogging();

    app.UseExceptionHandler();

    // One structured log line per request: method, path, status code, elapsed
    // ms. This is the "what happened" log; GlobalExceptionHandler's own logs
    // are the "what went wrong" detail for the subset of requests that failed.
    app.UseSerilogRequestLogging();

    // Must run before UseAuthorization() (added in Phase 6) — otherwise a
    // request rejected for auth reasons never gets CORS headers attached,
    // and the browser reports a misleading CORS error instead of the real
    // 401/403.
    app.UseCors("AngularApp");

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
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "IncidentPlatform.Api terminated unexpectedly during startup");
}
finally
{
    Log.CloseAndFlush();
}

// Exposed so integration tests can host the application through
// WebApplicationFactory<Program>. Top-level statements otherwise generate an
// internal Program class that the test project cannot reference.
public partial class Program;
