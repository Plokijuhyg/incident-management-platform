using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

// A completed assessment auto-promotes its real findings into the SOC Alerts pipeline:
// one PenTest Alert per finding, raw tool output in RawPayload and the model analysis in
// Description (separate fields), informational/open-port inventory excluded, and exactly once.
public class AssessmentAlertPromotionTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public AssessmentAlertPromotionTests(TestApiFactory factory) => _factory = factory;

    // One real finding, one informational open-service row, one unclassified finding (guard target).
    private const string Observations =
        """
        [
          {"kind":"Observed open service","port":"445","service":"microsoft-ds","severity":"Informational","evidence":"Nmap XML port element"},
          {"kind":"Finding","tool":"nmap_advanced_scan","endpoint":"192.168.0.110:445","cve":"CVE-2017-0143","title":"SMB MS17-010","severity":"High","evidence":"Host is likely VULNERABLE to MS17-010! raw nse output"},
          {"kind":"Finding","tool":"nikto_scan","endpoint":"192.168.0.110:80","title":"Server banner","severity":"Unclassified","evidence":"banner text"}
        ]
        """;

    private static SecurityAssessment CompletedJob(int requestedById = 0) => new()
    {
        RequestedById = requestedById,
        Status = "Completed",
        TargetName = "metasploitable3",
        TargetIp = "192.168.0.110",
        FinishedAt = DateTime.UtcNow,
        EvidenceSha256 = new string('A', 64),
        ObservationsJson = Observations,
    };

    [Fact]
    public void BuildPenTestAlerts_promotes_only_real_findings_with_separated_fields()
    {
        const string analysis = "Model brief: this host is exploitable via EternalBlue; patch MS17-010.";
        var alerts = AssessmentWorker.BuildPenTestAlerts(CompletedJob(), analysis);

        // Open-service inventory and the unclassified finding are excluded -> exactly one alert.
        var alert = Assert.Single(alerts);
        Assert.Equal(AlertSource.PenTest, alert.Source);
        Assert.Equal(AlertStatus.New, alert.Status);
        Assert.Equal("High", alert.Severity);
        Assert.Equal("CVE-2017-0143", alert.SourceRuleId);
        Assert.Equal("192.168.0.110", alert.EntityIp);
        Assert.StartsWith("pentest:", alert.DeduplicationKey);

        // RawPayload = verbatim tool evidence; Description = model analysis; never blended.
        Assert.Contains("VULNERABLE to MS17-010", alert.RawPayload);
        Assert.Contains("CVE-2017-0143", alert.RawPayload);
        Assert.Equal(analysis, alert.Description);
        Assert.DoesNotContain("EternalBlue", alert.RawPayload);         // model text not in raw
        Assert.DoesNotContain("VULNERABLE", alert.Description!);        // raw not in description
    }

    [Fact]
    public void BuildPenTestAlerts_raises_nothing_for_a_connectivity_failure_assessment()
    {
        // "no route to host" / all-errors runs yield no findings, so no alerts are promoted.
        var job = CompletedJob();
        job.ObservationsJson = """[{"kind":"Observed open service","port":"445","service":"microsoft-ds","severity":"Informational","evidence":"x"}]""";
        Assert.Empty(AssessmentWorker.BuildPenTestAlerts(job, "irrelevant"));

        var failed = CompletedJob();
        failed.Status = "Failed";
        Assert.Empty(AssessmentWorker.BuildPenTestAlerts(failed, "irrelevant"));
    }

    [Fact]
    public async Task PromoteFindingsAsync_creates_one_alert_per_finding_exactly_once()
    {
        int userId;
        string jobId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            userId = await db.Users.Select(u => u.Id).FirstAsync();
            var job = CompletedJob(userId);
            db.SecurityAssessments.Add(job);
            await db.SaveChangesAsync();
            jobId = job.Id;

            // First completion.
            var first = await AssessmentWorker.PromoteFindingsAsync(db, job, "Model analysis A.", default);
            await db.SaveChangesAsync();
            Assert.Equal(1, first);

            // A duplicate completion (e.g. a failed save retried) must add nothing.
            var second = await AssessmentWorker.PromoteFindingsAsync(db, job, "Model analysis A.", default);
            await db.SaveChangesAsync();
            Assert.Equal(0, second);
        }

        try
        {
            using var verify = _factory.Services.CreateScope();
            var db = verify.ServiceProvider.GetRequiredService<AppDbContext>();
            var alerts = await db.Alerts.AsNoTracking()
                .Where(a => a.Source == AlertSource.PenTest && a.DeduplicationKey!.StartsWith("pentest:" + jobId))
                .ToListAsync();

            var alert = Assert.Single(alerts); // exactly once despite two promotion calls
            Assert.Equal("High", alert.Severity);
            Assert.Contains("VULNERABLE to MS17-010", alert.RawPayload);
            Assert.Equal("Model analysis A.", alert.Description);
        }
        finally
        {
            using var scope = _factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Alerts.Where(a => a.DeduplicationKey!.StartsWith("pentest:" + jobId)).ExecuteDeleteAsync();
            await db.AuditLogs.Where(a => a.EntityId == jobId).ExecuteDeleteAsync();
            await db.SecurityAssessments.Where(a => a.Id == jobId).ExecuteDeleteAsync();
        }
    }
}
