using FluentValidation;
using FluentValidation.AspNetCore;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Middleware;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
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
    builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

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
    builder.Services.AddSingleton<ApprovedLabTargets>();
    builder.Services.AddScoped<TelemetryAccess>();
    builder.Services.AddSingleton<AssessmentGateway>();
    builder.Services.AddScoped<AssessmentService>();
    builder.Services.AddSingleton<OllamaAnalysis>();
    builder.Services.AddHttpClient("Ollama",client=>client.Timeout=Timeout.InfiniteTimeSpan).RemoveAllLoggers().ConfigurePrimaryHttpMessageHandler(()=>new HttpClientHandler{AllowAutoRedirect=false,UseProxy=false});
    builder.Services.AddHostedService<AssessmentWorker>();
    builder.Services.AddHttpClient("AssessmentGateway").ConfigurePrimaryHttpMessageHandler(() => {
        var handler=new HttpClientHandler { AllowAutoRedirect=false, UseProxy=false };
        var certificate=builder.Configuration["HexStrike:ClientCertificatePath"];
        if(!string.IsNullOrWhiteSpace(certificate))handler.ClientCertificates.Add(System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12FromFile(certificate,builder.Configuration["HexStrike:ClientCertificatePassword"]));
        var caPath=builder.Configuration["HexStrike:ServerCaCertificatePath"];
        if(!string.IsNullOrWhiteSpace(caPath))
        {
            var ca=System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(caPath);
            handler.ServerCertificateCustomValidationCallback=(_, certificate, _, errors) =>
            {
                if(certificate is null || (errors & ~System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)!=0) return false;
                using var chain=new System.Security.Cryptography.X509Certificates.X509Chain();
                chain.ChainPolicy.TrustMode=System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                // Dedicated offline lab CA has no revocation service. Certificate lifetime still applies.
                chain.ChainPolicy.RevocationMode=System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(certificate);
            };
        }
        return handler;
    });
    builder.Services.AddScoped<AutomationProcessor>();
    builder.Services.AddSingleton<AutomationWorker>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<AutomationWorker>());
    builder.Services.AddSingleton<WindowsEventCollector>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<WindowsEventCollector>());
    builder.Services.AddScoped<IWorkspaceService, WorkspaceService>();
    builder.Services.AddScoped<LabConnections>();
    builder.Services.AddSingleton<VirusTotalClient>();
    builder.Services.AddScoped<IIncidentEmailSender,SmtpIncidentEmailSender>();
    builder.Services.AddScoped<IncidentNotificationProcessor>();
    builder.Services.AddHostedService<IncidentNotificationWorker>();
    builder.Services.AddHttpClient("VirusTotal").RemoveAllLoggers().ConfigurePrimaryHttpMessageHandler(()=>new HttpClientHandler{AllowAutoRedirect=false});
    builder.Services.AddHttpClient("LabConnections").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false });
    builder.Services.AddOpenApi();
    builder.Services.AddHealthChecks().AddCheck<DatabaseReadinessCheck>("mysql", tags: ["ready"],
        timeout: TimeSpan.FromSeconds(5));
    builder.Services.AddApiRateLimiting();
    builder.Services.AddScoped<IAuditContext, RequestAuditContext>();
    builder.Services.AddScoped<IDashboardService, DashboardService>();
    builder.Services.AddProblemDetails();
    builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
    builder.Services.AddScoped<IUserService, UserService>();
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<ICurrentUser, CurrentUser>();
    builder.Services.AddScoped<IIncidentService, IncidentService>();
    builder.Services.AddScoped<IIocService, IocService>();
    builder.Services.AddScoped<IAlertService, AlertService>();
    builder.Services.AddScoped<IAssetService, AssetService>();
    builder.Services.AddScoped<IMitreService, MitreService>();
    builder.Services.AddScoped<IIncidentSubResourceService, IncidentSubResourceService>();
    builder.Services
        .AddOptions<CorsSettings>()
        .Bind(builder.Configuration.GetSection(CorsSettings.SectionName))
        .ValidateDataAnnotations()
        .ValidateOnStart();

    builder.Services
    .AddOptions<EvidenceStorageSettings>()
    .Bind(builder.Configuration.GetSection(EvidenceStorageSettings.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

    builder.Services.AddScoped<IEvidenceService, EvidenceService>();

    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException(
            "Connection string 'DefaultConnection' not found. " +
            "Run 'dotnet user-secrets set \"ConnectionStrings:DefaultConnection\" \"...\"' in the API project.");

    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 0))));

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

    // JWT Bearer authentication â€” read directly from configuration (same
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
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    var principal = context.Principal!;
                    if (!int.TryParse(principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value, out var id))
                    {
                        context.Fail("Invalid user.");
                        return;
                    }
                    var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
                    var user = await db.Users.AsNoTracking().Include(u => u.UserRoles).ThenInclude(r => r.Role)
                        .SingleOrDefaultAsync(u => u.Id == id, context.HttpContext.RequestAborted);
                    if (user?.IsActive != true)
                    {
                        context.Fail("Invalid user.");
                        return;
                    }
                    var credentialVersion=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(user.PasswordHash)));
                    if(principal.FindFirst("pwdv")?.Value!=credentialVersion){context.Fail("Credentials changed. Sign in again.");return;}
                    var identity = (System.Security.Claims.ClaimsIdentity)principal.Identity!;
                    foreach (var claim in identity.FindAll(System.Security.Claims.ClaimTypes.Role).ToList())
                        identity.RemoveClaim(claim);
                    foreach (var role in user.UserRoles)
                        identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, role.Role.Name));
                }
            };
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
    // HTTP pipeline (order per docs/architecture.md Â§4)
    // -------------------------------------------------------------------
    app.UseMiddleware<SecurityHeadersMiddleware>();
    app.UseSerilogRequestLogging();
    app.UseExceptionHandler();
    if (!app.Environment.IsDevelopment()) app.UseHsts();
    app.UseHttpsRedirection();
    app.UseRouting();
    app.UseCors("AngularApp");
    app.UseAuthentication();
    app.UseMiddleware<AuditMiddleware>();
    // Inner handler translates service errors before the audit middleware observes them.
    app.UseExceptionHandler();
    app.UseMiddleware<LoginIdentityMiddleware>();
    app.UseRateLimiter();
    app.UseAuthorization();

    if (!app.Environment.IsProduction())
    {
        app.MapOpenApi();
    }

    app.MapControllers();
    app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
    {
        Predicate = _ => false
    }).DisableRateLimiting();
    app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
    {
        Predicate = check => check.Tags.Contains("ready")
    }).DisableRateLimiting();

    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var seedLogger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

        var adminEmail = app.Configuration["Admin:Email"];
        var adminPassword = app.Configuration["Admin:Password"];

        await DataSeeder.SeedAsync(dbContext, passwordHasher, adminEmail, adminPassword, seedLogger);
        await MitreSeedData.SeedAsync(dbContext);

        var connectorEmail = app.Configuration["Integration:HexStrikeEmail"];
        var connectorPassword = app.Configuration["Integration:HexStrikePassword"];
        await DataSeeder.SeedIntegrationAccountAsync(dbContext, passwordHasher, connectorEmail, connectorPassword, seedLogger);
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
