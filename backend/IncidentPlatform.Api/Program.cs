using IncidentPlatform.Api.Middleware;
using Serilog;
using Serilog.Formatting.Compact;
using Microsoft.Extensions.Hosting;
using IncidentPlatform.Api.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using IncidentPlatform.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using IncidentPlatform.Api.Authentication;

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
    // WebApplicationFactory-hosted tests invoke this Main() directly and
    // don't inherit ASPNETCORE_ENVIRONMENT from launchSettings.json — so the
    // test host reports "Production", and CreateBuilder's automatic User
    // Secrets loading (which only triggers in Development) never runs. Added
    // explicitly here so local dev and the test host both read the same
    // secrets.json regardless of which environment name the process reports.
    // optional: true means this is a no-op with no error on a real
    // deployment, where no secrets.json file exists at all.
    builder.Configuration.AddUserSecrets<Program>(optional: true);

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

    // Password hashing — standalone Identity PasswordHasher, not the full
    // Identity framework (see Authentication/PasswordHasher.cs for why).
    builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();

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
    
        // MySQL via Pomelo. ServerVersion.AutoDetect connects once at startup to
    // ask MySQL its own version — this lets EF Core generate SQL that matches
    // the actual server (8.0.43) rather than guessing, which matters for
    // features like JSON columns (used by Alerts.RawPayload later) that
    // differ across MySQL versions.
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException(
            "Connection string 'DefaultConnection' not found. " +
            "Run 'dotnet user-secrets set \"ConnectionStrings:DefaultConnection\" \"...\"' in the API project.");

    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

          // CORS policy itself. Bound directly from configuration once, here —
    // not via BuildServiceProvider() (which would create a second, wasteful
    // copy of every singleton service just to read one settings object).
    // The AddOptions<CorsSettings> registration above still provides
    // ValidateOnStart() fail-fast behavior for the app as a whole; this is
    // just the one place that needs the value before the container exists.
    var corsSettings = builder.Configuration
        .GetSection(CorsSettings.SectionName)
        .Get<CorsSettings>()
        ?? throw new InvalidOperationException("Cors configuration section is missing.");

    builder.Services.AddCors(corsOptions =>
    {
        corsOptions.AddPolicy("AngularApp", policy =>
        {
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

    // Idempotent reference-data seeding, run once per startup. Scoped
    // because AppDbContext is registered as scoped (EF Core's default) —
    // resolving it here at the app root requires creating a scope manually,
    // since Program.cs runs outside any HTTP request's own scope.
    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await DataSeeder.SeedAsync(dbContext);
    }

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
