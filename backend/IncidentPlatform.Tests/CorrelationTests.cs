using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services.Correlation;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

public class CorrelationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public CorrelationTests(TestApiFactory factory) => _factory = factory;

    private Alert NewAlert(string host, string severity, string token) => new()
    {
        Title = "Signal on " + host,
        Source = AlertSource.Firewall,
        SourceRuleId = "LOG-CRITICAL-SEVERITY",
        Severity = severity,
        Status = AlertStatus.New,
        Host = host,
        DeduplicationKey = "corr-test:" + token + ":" + Guid.NewGuid().ToString("N"),
        DetectedAt = DateTime.UtcNow,
        ReceivedAt = DateTime.UtcNow,
    };

    [Fact]
    public async Task Three_related_alerts_open_one_tiered_case_and_a_lone_alert_does_not()
    {
        var host = "HOST-" + Guid.NewGuid().ToString("N")[..8];
        var lonelyHost = "HOST-" + Guid.NewGuid().ToString("N")[..8];
        var token = Guid.NewGuid().ToString("N")[..8];
        var alertIds = new List<int>();
        try
        {
            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                // Ensure a system actor (active admin) exists for the engine.
                if (!await db.Users.AnyAsync(u => u.IsActive && u.UserRoles.Any(r => r.Role.Name == RoleNames.Admin)))
                {
                    var hasher = scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Authentication.IPasswordHasher>();
                    var admin = new User { Email = $"corr-admin-{token}@example.com", FullName = "Corr Admin", PasswordHash = hasher.Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
                    db.Users.Add(admin); await db.SaveChangesAsync();
                    var role = await db.Roles.SingleAsync(r => r.Name == RoleNames.Admin);
                    db.UserRoles.Add(new UserRole { UserId = admin.Id, RoleId = role.Id, AssignedAt = DateTime.UtcNow, AssignedById = admin.Id });
                    await db.SaveChangesAsync();
                }
                foreach (var _ in Enumerable.Range(0, 3)) db.Alerts.Add(NewAlert(host, "Medium", token));
                db.Alerts.Add(NewAlert(lonelyHost, "Medium", token)); // single alert — no case
                await db.SaveChangesAsync();
                alertIds = await db.Alerts.Where(a => a.DeduplicationKey!.StartsWith("corr-test:" + token)).Select(a => a.Id).ToListAsync();
            }

            using (var scope = _factory.Services.CreateScope())
                await scope.ServiceProvider.GetRequiredService<CorrelationEngine>().RunAsync(default);

            using (var scope = _factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var incident = await db.Incidents.SingleOrDefaultAsync(i => i.CorrelationKey == "host:" + host.ToUpperInvariant());
                Assert.NotNull(incident);
                Assert.Equal(IncidentSource.Correlation, incident!.Source);
                Assert.Equal(1, incident.Tier);
                Assert.NotNull(incident.SlaDueAt);
                var linked = await db.Alerts.CountAsync(a => a.IncidentId == incident.Id && a.Status == AlertStatus.Promoted);
                Assert.Equal(3, linked);
                // The single alert on the other host stayed New and unlinked.
                Assert.False(await db.Incidents.AnyAsync(i => i.CorrelationKey == "host:" + lonelyHost.ToUpperInvariant()));
                Assert.True(await db.Alerts.AnyAsync(a => a.Host == lonelyHost && a.Status == AlertStatus.New && a.IncidentId == null));
            }
        }
        finally
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var incidentIds = await db.Incidents.Where(i => i.CorrelationKey == "host:" + host.ToUpperInvariant()).Select(i => i.Id).ToListAsync();
            await db.IncidentTimelineEvents.Where(t => incidentIds.Contains(t.IncidentId)).ExecuteDeleteAsync();
            await db.Alerts.Where(a => a.DeduplicationKey!.StartsWith("corr-test:" + token)).ExecuteDeleteAsync();
            await db.Incidents.Where(i => incidentIds.Contains(i.Id)).ExecuteDeleteAsync();
            await db.AuditLogs.Where(a => a.ActorEmail == "system:correlation" && incidentIds.Select(x => x.ToString()).Contains(a.EntityId!)).ExecuteDeleteAsync();
            var admin = await db.Users.SingleOrDefaultAsync(u => u.Email == $"corr-admin-{token}@example.com");
            if (admin is not null) { db.UserRoles.RemoveRange(db.UserRoles.Where(r => r.UserId == admin.Id)); db.Users.Remove(admin); await db.SaveChangesAsync(); }
        }
    }
}
