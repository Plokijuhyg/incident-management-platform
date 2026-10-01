using IncidentPlatform.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace IncidentPlatform.Tests;

public class DatabaseReadinessTests
{
    [Fact]
    public async Task Unreachable_mysql_reports_unhealthy_without_exposing_connection_details()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>().UseMySql(
            "Server=127.0.0.1;Port=1;User ID=unavailable;Password=unused;Database=unavailable;Connection Timeout=1;",
            new MySqlServerVersion(new Version(8, 0, 0))).Options;
        await using var db = new AppDbContext(options);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await new DatabaseReadinessCheck(db).CheckHealthAsync(new HealthCheckContext(), timeout.Token);
        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Null(result.Exception);
        Assert.Null(result.Description);
        Assert.Empty(result.Data);
    }
}
