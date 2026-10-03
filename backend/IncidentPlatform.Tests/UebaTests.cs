using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services.Ueba;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class UebaTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public UebaTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Failed_login_spike_builds_a_baseline_and_raises_a_ueba_alert()
    {
        var user = "svc_" + Guid.NewGuid().ToString("N")[..8];
        var source = "ueba-" + Guid.NewGuid().ToString("N")[..8];
        var baseTime = DateTime.UtcNow.AddMinutes(-5);
        try
        {
            long fromId;
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                fromId = await db.LogEvents.MaxAsync(e => (long?)e.Id) ?? 0;
                for (var i = 0; i < 6; i++)
                    db.LogEvents.Add(new LogEvent
                    {
                        Source = source, SourceType = LogSourceType.Vpn, Fingerprint = Guid.NewGuid().ToString("N"),
                        User = user, Action = "login", Outcome = "failure", SourceIp = "203.0.113." + i,
                        Message = "auth fail", RawLog = "raw", Severity = 5,
                        EventTime = baseTime.AddSeconds(i * 10), ReceivedAt = DateTime.UtcNow,
                    });
                await db.SaveChangesAsync();
            }

            using (var scope = _factory.Services.CreateScope())
            {
                var cursor = await scope.ServiceProvider.GetRequiredService<UebaEngine>().ProcessAsync(fromId, 500, default);
                Assert.True(cursor > fromId);
            }

            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var profile = await db.EntityProfiles.SingleOrDefaultAsync(p => p.EntityType == "user" && p.EntityValue == user);
                Assert.NotNull(profile);
                Assert.True(profile!.FailedLoginsHour >= UebaEngine.FailedLoginThreshold);
                Assert.True(profile.RiskScore > 0);

                var alert = await db.Alerts.SingleOrDefaultAsync(a => a.Source == AlertSource.Ueba && a.Username == user);
                Assert.NotNull(alert);
                Assert.Equal("UEBA-FAILED-LOGIN-SPIKE", alert!.SourceRuleId);
                Assert.Equal(AlertStatus.New, alert.Status);
            }
        }
        finally
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Alerts.Where(a => a.Source == AlertSource.Ueba && a.Username == user).ExecuteDeleteAsync();
            await db.LogEvents.Where(e => e.Source == source).ExecuteDeleteAsync();
            await db.EntityProfiles.Where(p => p.EntityValue == user).ExecuteDeleteAsync();
            await db.AuditLogs.Where(a => a.ActorEmail == "system:ueba" && a.EntityId == user).ExecuteDeleteAsync();
        }
    }
}
