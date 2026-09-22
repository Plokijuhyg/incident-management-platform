using FluentValidation;
using FluentValidation.AspNetCore;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Middleware;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Formatting.Compact;
using System.Text;

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

    builder.Configuration.AddUserSecrets<Program>(optional: true);

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

    // -------------------------------------------------------------------
    // Services
    // -------------------------------------------------------------------
    builder.Services.AddControllers();
    builder.Services.AddOpenApi();
    builder.Services.AddHealthChecks();
    builder.Services.AddProblemDetails();
    builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

    builder.Services
        .AddOptions<CorsSettings>()
        .Bind(builder.Configuration.GetSection(CorsSettings.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException(
            "Connection string 'DefaultConnection' not found. " +
            "Run 'dotnet user-secrets set \"ConnectionStrings:DefaultConnection\" \"...\"' in the API project.");

    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

    builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();

    builder.Services
        .AddOptions<JwtSettings>()
        .Bind(builder.Configuration.GetSection(JwtSettings.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    builder.Services.AddSingleton<IJwtService, JwtService>();
    builder.Services.AddScoped<IAuthService, AuthService>();

    builder.Services.AddValidatorsFromAssemblyContaining<Program>();
    builder.Services.AddFluentValidationAutoValidation();

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

    // JWT Bearer authentication — read directly from configuration (same
    // pattern as CorsSettings above), needed before the container is built.
    var jwtSettingsForAuth = builder.Configuration
        .GetSection(JwtSettings.SectionName)
        .Get<JwtSettings>()
        ?? throw new InvalidOperationException("Jwt configuration section is missing.");

    builder.Services
        .AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtSettingsForAuth.Issuer,
                ValidateAudience = true,
                ValidAudience = jwtSettingsForAuth.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettingsForAuth.Secret)),
                ValidateLifetime = true
            };
        });

    builder.Services.AddAuthorization();

    var app = builder.Build();

    // -------------------------------------------------------------------
    // HTTP pipeline (order per docs/architecture.md §4)
    // -------------------------------------------------------------------
    app.UseSerilogRequestLogging();
    app.UseExceptionHandler();
    app.UseCors("AngularApp");
    app.UseAuthentication();
    app.UseAuthorization();

    if (!app.Environment.IsProduction())
    {
        app.MapOpenApi();
    }

    app.UseHttpsRedirection();
    app.MapControllers();
    app.MapHealthChecks("/health");

    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var seedLogger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

        var adminEmail = app.Configuration["Admin:Email"];
        var adminPassword = app.Configuration["Admin:Password"];

        await DataSeeder.SeedAsync(dbContext, passwordHasher, adminEmail, adminPassword, seedLogger);
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

public partial class Program;
