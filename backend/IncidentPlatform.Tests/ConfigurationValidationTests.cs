using IncidentPlatform.Api.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace IncidentPlatform.Tests;

/// <summary>
/// Tests the CorsSettings validation rule directly against a minimal
/// ServiceCollection — not a full WebApplication/Kestrel host. Accessing
/// IOptions&lt;T&gt;.Value is what actually triggers validation; that's the
/// same mechanism ValidateOnStart() relies on internally, just exercised
/// directly instead of through the full host startup sequence.
/// </summary>
public class ConfigurationValidationTests
{
    private static IOptions<CorsSettings> BuildCorsOptions(Dictionary<string, string?> configValues)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configValues)
            .Build();

        var services = new ServiceCollection();
        services
            .AddOptions<CorsSettings>()
            .Bind(configuration.GetSection(CorsSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services.BuildServiceProvider().GetRequiredService<IOptions<CorsSettings>>();
    }

    [Fact]
    public void EmptyAllowedOrigins_FailsValidationOnAccess()
    {
        var options = BuildCorsOptions(new Dictionary<string, string?>());

        var ex = Assert.Throws<OptionsValidationException>(() => options.Value);

        Assert.Contains("AllowedOrigins", ex.Message);
    }

    [Fact]
    public void ValidAllowedOrigins_BindsSuccessfully()
    {
        var options = BuildCorsOptions(new Dictionary<string, string?>
        {
            ["Cors:AllowedOrigins:0"] = "http://localhost:4200"
        });

        var settings = options.Value;

        Assert.Single(settings.AllowedOrigins);
        Assert.Equal("http://localhost:4200", settings.AllowedOrigins[0]);
    }
}