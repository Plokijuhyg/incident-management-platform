using IncidentPlatform.Api.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MySqlConnector;
namespace IncidentPlatform.Tests;

public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    public TestApiFactory() { ClientOptions.BaseAddress = new Uri("https://localhost"); }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        // Integration fixtures must not inherit a running real Kali gateway from user secrets.
        builder.ConfigureAppConfiguration((_,config)=>config.AddInMemoryCollection(new Dictionary<string,string?> { ["HexStrike:Enabled"]="false", ["VirusTotal:ApiKey"]="", ["Notifications:Enabled"]="false", ["Ollama:Enabled"]="false",
            // Log ingestion on, with one known key: SHA-256 of "test-ingest-key-0001".
            ["Ingestion:Enabled"]="true", ["Ingestion:Keys:0"]="280B09A38F5DCA421B24E427AFE37027D21F49EFC975DFE2A86CEC4105808778" }));
        builder.ConfigureServices(services =>
        {
            var settings=new ConfigurationBuilder().AddUserSecrets<Program>().AddEnvironmentVariables().Build();
            var connection=new MySqlConnectionStringBuilder(settings.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Database configuration is required."));
            connection.Database += "_tests";
            if(!connection.Database.EndsWith("_tests",StringComparison.Ordinal))throw new InvalidOperationException("Tests require a separate database.");
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<AppDbContext>>();
            services.AddDbContext<AppDbContext>(options=>options.UseMySql(connection.ConnectionString,new MySqlServerVersion(new Version(8,0,0))));
            using var db=new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseMySql(connection.ConnectionString,new MySqlServerVersion(new Version(8,0,0))).Options);
            db.Database.Migrate();
        });
    }
}
