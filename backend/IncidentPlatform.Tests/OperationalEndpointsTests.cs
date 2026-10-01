using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.DTOs.Dashboard;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.DTOs.Users;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace IncidentPlatform.Tests;

public class OperationalEndpointsTests : IClassFixture<TestApiFactory>, IAsyncLifetime
{
    private readonly TestApiFactory factory;
    private readonly string email = $"operations-{Guid.NewGuid():N}@example.com";
    private readonly List<int> users = [];
    private HttpClient client = null!;
    private int actorId;
    private const string Password = "Password123!";

    public OperationalEndpointsTests(TestApiFactory factory) => this.factory = factory;

    public async Task InitializeAsync()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var user = new User { Email = email, FullName = "Operations test", PasswordHash = hasher.Hash(Password),
            IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        actorId = user.Id;
        users.Add(actorId);
        var admin = await db.Roles.SingleAsync(r => r.Name == RoleNames.Admin);
        db.UserRoles.Add(new UserRole { UserId = actorId, RoleId = admin.Id, AssignedById = actorId, AssignedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
        client = await Login(email);
    }

    private async Task<HttpClient> Login(string address)
    {
        var http = factory.CreateClient();
        var response = await http.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = address, Password = Password });
        response.EnsureSuccessStatusCode();
        var login = (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);
        return http;
    }

    public async Task DisposeAsync()
    {
        client?.Dispose();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var storage = scope.ServiceProvider.GetRequiredService<IOptions<EvidenceStorageSettings>>().Value;
        var files = await db.Evidence.Where(e => users.Contains(e.UploadedById)).Select(e => e.StoredFileName).ToListAsync();
        foreach (var file in files) File.Delete(Path.Combine(storage.RootPath, file));
        db.Incidents.RemoveRange(db.Incidents.Where(i => users.Contains(i.CreatedById)));
        db.RefreshTokens.RemoveRange(db.RefreshTokens.Where(t => users.Contains(t.UserId)));
        db.UserRoles.RemoveRange(db.UserRoles.Where(r => users.Contains(r.UserId) || users.Contains(r.AssignedById)));
        db.AuditLogs.RemoveRange(db.AuditLogs.Where(a => (a.ActorUserId != null && users.Contains(a.ActorUserId.Value)) || a.ActorEmail == email));
        db.Users.RemoveRange(db.Users.Where(u => users.Contains(u.Id)));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task User_roles_apply_to_existing_tokens_and_deactivation_blocks_access_and_refresh()
    {
        var response = await client.PostAsJsonAsync("/api/users", new CreateUserRequest
        {
            Email = $"target-{Guid.NewGuid():N}@example.com", FullName = "Target", Password = Password,
            Roles = [RoleNames.SocAnalyst]
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var target = (await response.Content.ReadFromJsonAsync<UserResponse>())!;
        users.Add(target.Id);
        using var targetClient = await Login(target.Email);
        Assert.Equal(HttpStatusCode.Forbidden, (await targetClient.GetAsync("/api/users")).StatusCode);
        // Retaining the existing role must not cause a duplicate tracked composite key.
        for (var n = 0; n < 2; n++)
        {
            var roles = await client.PostAsJsonAsync($"/api/users/{target.Id}/roles",
                new ReplaceRolesRequest { Roles = [RoleNames.SocAnalyst, RoleNames.Admin] });
            Assert.Equal(HttpStatusCode.OK, roles.StatusCode);
        }
        Assert.Equal(HttpStatusCode.OK, (await targetClient.GetAsync("/api/users")).StatusCode);
        var ownRoleRemoval = await client.PostAsJsonAsync($"/api/users/{actorId}/roles",
            new ReplaceRolesRequest { Roles = [RoleNames.SocAnalyst] });
        Assert.Equal(HttpStatusCode.BadRequest, ownRoleRemoval.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync($"/api/users/{target.Id}/deactivate", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await targetClient.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await targetClient.PostAsync("/api/auth/refresh", null)).StatusCode);
        var assignable = (await client.GetFromJsonAsync<List<AssignableUserResponse>>("/api/users/assignable"))!;
        Assert.DoesNotContain(assignable, u => u.Id == target.Id);
    }

    [Fact]
    public async Task Audit_captures_login_incident_changes_evidence_and_denials_without_secrets()
    {
        var created = await client.PostAsJsonAsync("/api/incidents", new IncidentCreateRequest
        {
            Title = "Audit test", Description = "sensitive-incident-description", Severity = IncidentSeverity.High,
            Category = IncidentCategory.Malware, Priority = IncidentPriority.High, Source = IncidentSource.Manual
        });
        created.EnsureSuccessStatusCode();
        var incident = (await created.Content.ReadFromJsonAsync<IncidentDetailResponse>())!;
        var updated = await client.PutAsJsonAsync($"/api/incidents/{incident.Id}", new IncidentUpdateRequest
        {
            Title = "Edited audit test", Description = "new-sensitive-description", Severity = IncidentSeverity.Critical,
            Priority = IncidentPriority.High, Category = IncidentCategory.Malware, Version = incident.Version
        });
        updated.EnsureSuccessStatusCode();
        using var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(System.Text.Encoding.UTF8.GetBytes("private-evidence-bytes"));
        file.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        form.Add(file, "file", "audit.txt");
        form.Add(new StringContent("LogFile"), "evidenceType");
        var uploaded = await client.PostAsync($"/api/incidents/{incident.Id}/evidence", form);
        uploaded.EnsureSuccessStatusCode();
        var evidence = await uploaded.Content.ReadFromJsonAsync<JsonElement>();
        var evidenceId = evidence.GetProperty("id").GetInt32();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/api/incidents/{incident.Id}/evidence/{evidenceId}/download")).StatusCode);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/users")).StatusCode);
        var failed = await anonymous.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "wrong-password-secret" });
        Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var logs = await db.AuditLogs.Where(a => a.ActorUserId == actorId || a.ActorEmail == email).ToListAsync();
        Assert.Contains(logs, a => a.Action == "LOGIN_SUCCEEDED" && a.ActorUserId == actorId);
        Assert.Contains(logs, a => a.Action == "LOGIN_FAILED" && a.Outcome == AuditOutcome.Failure);
        Assert.Contains(logs, a => a.Action == "INCIDENT_CREATED" && a.EntityId == incident.Id.ToString());
        var edit = Assert.Single(logs, a => a.Action == "INCIDENT_UPDATED" && a.EntityId == incident.Id.ToString());
        using var details = JsonDocument.Parse(edit.Details!);
        Assert.Equal((int)IncidentSeverity.High, details.RootElement.GetProperty("Severity").GetProperty("before").GetInt32());
        Assert.Equal((int)IncidentSeverity.Critical, details.RootElement.GetProperty("Severity").GetProperty("after").GetInt32());
        Assert.Contains(logs, a => a.Action == "EVIDENCE_UPLOADED" && a.EntityId == evidenceId.ToString());
        Assert.Contains(logs, a => a.Action == "EVIDENCE_DOWNLOADED" && a.EntityId == evidenceId.ToString());
        var serialized = JsonSerializer.Serialize(logs.Select(a => a.Details));
        foreach (var secret in new[] { Password, "wrong-password-secret", "private-evidence-bytes", "sensitive-incident-description" })
            Assert.DoesNotContain(secret, serialized);
        Assert.True(await db.AuditLogs.AnyAsync(a => a.Action == "ACCESS_DENIED" && a.Outcome == AuditOutcome.Denied));
    }

    [Fact]
    public async Task Audit_failure_rolls_back_business_write()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var options = scope.ServiceProvider.GetRequiredService<DbContextOptions<AppDbContext>>();
        await using var failing = new AppDbContext(options, new FailingAudit());
        var number = "T-" + Guid.NewGuid().ToString("N")[..16];
        failing.Incidents.Add(new Incident { IncidentNumber = number, Title = "Rollback", Description = "test",
            CreatedById = actorId, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing.SaveChangesAsync());
        Assert.False(await db.Incidents.AnyAsync(i => i.IncidentNumber == number));
    }

    [Fact]
    public async Task Workspace_reads_are_scoped_and_PenTest_alerts_promote()
    {
        var created=await client.PostAsJsonAsync("/api/alerts",new {title="PenTest UI contract",description="Observed evidence",source=6,severity="High",detectedAt=DateTime.UtcNow,rawPayload="{\"tool\":\"fixture\"}"});
        created.EnsureSuccessStatusCode();
        var alert=(await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt32();
        try {
            var promoted=await client.PostAsJsonAsync($"/api/alerts/{alert}/promote",new {title="PenTest promotion",severity=2,priority=1,category=7});
            promoted.EnsureSuccessStatusCode();
            var incident=(await promoted.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetInt32();
            foreach(var resource in new[]{"iocs","assets","mitre-techniques"}) {
                var rows=await client.GetFromJsonAsync<JsonElement>($"/api/incidents/{incident}/{resource}");
                Assert.Equal(0,rows.GetArrayLength());
                Assert.Equal(HttpStatusCode.NotFound,(await client.GetAsync($"/api/incidents/2147483647/{resource}")).StatusCode);
            }
            var audit=await client.GetFromJsonAsync<JsonElement>($"/api/audit-logs?entityType=Incident&entityId={incident}&pageSize=1");
            Assert.Equal(1,audit.GetProperty("pageSize").GetInt32());
            Assert.True(audit.GetProperty("totalCount").GetInt32()>0);
            Assert.Equal(incident.ToString(),audit.GetProperty("items")[0].GetProperty("entityId").GetString());
            Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync("/api/audit-logs?outcome=55")).StatusCode);
            using var anonymous=factory.CreateClient();
            Assert.Equal(HttpStatusCode.Unauthorized,(await anonymous.GetAsync("/api/audit-logs")).StatusCode);
            Assert.Equal(HttpStatusCode.OK,(await client.GetAsync("/api/lab/connections")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsync("/api/lab/connections/unknown/check",null)).StatusCode);
        } finally {
            using var scope=factory.Services.CreateScope();
            var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Alerts.RemoveRange(db.Alerts.Where(a=>a.Id==alert));await db.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task Windows_events_preserve_raw_data_and_assessments_stay_disabled_without_Kali()
    {
        long eventId;
        using(var scope=factory.Services.CreateScope()){
            var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var e=new WindowsEvent{Fingerprint=Guid.NewGuid().ToString("N"),Machine="isolated-test",Channel="TestChannel",Provider="TestProvider",EventId=4624,ReceivedAt=DateTime.UtcNow,Message="<script>fixture</script>",RawXml="<Event/>"};db.Add(e);await db.SaveChangesAsync();eventId=e.Id;
        }
        try {
            var list=await client.GetFromJsonAsync<JsonElement>("/api/windows-events?channel=TestChannel&eventId=4624");Assert.Contains(list.GetProperty("items").EnumerateArray(),x=>x.GetProperty("id").GetInt64()==eventId);
            var detail=await client.GetFromJsonAsync<JsonElement>($"/api/windows-events/{eventId}");Assert.Equal("<Event/>",detail.GetProperty("rawXml").GetString());
            var status=await client.GetFromJsonAsync<JsonElement>("/api/windows-events/status");Assert.False(status.GetProperty("enabled").GetBoolean());
            var activity=await client.GetFromJsonAsync<JsonElement>("/api/windows-events/activity");
            Assert.Equal(30,activity.GetProperty("timeline").GetArrayLength());
            Assert.True(activity.GetProperty("eventsLastMinute").GetInt32() >= 1);
            Assert.Contains(activity.GetProperty("latest").EnumerateArray(),x=>x.GetProperty("id").GetInt64()==eventId);
            Assert.Contains(activity.GetProperty("topChannels").EnumerateArray(),x=>x.GetProperty("label").GetString()=="TestChannel" && x.GetProperty("count").GetInt32()>=1);
            Assert.True(activity.GetProperty("timeline").EnumerateArray().Sum(x=>x.GetProperty("count").GetInt32())>=1);
            var caps=await client.GetFromJsonAsync<JsonElement>("/api/assessments/capabilities");Assert.False(caps.GetProperty("connected").GetBoolean());Assert.Equal(0,caps.GetProperty("profiles").GetArrayLength());
            Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsJsonAsync("/api/assessments",new{targetId="unknown",profile="tcp-services"})).StatusCode);
            using var anonymous=factory.CreateClient();Assert.Equal(HttpStatusCode.Unauthorized,(await anonymous.GetAsync("/api/windows-events")).StatusCode);
            await client.PostAsJsonAsync($"/api/users/{actorId}/roles",new ReplaceRolesRequest{Roles=[RoleNames.Admin,RoleNames.SocAnalyst]});
        } finally {using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();await db.WindowsEvents.Where(x=>x.Id==eventId).ExecuteDeleteAsync();}
    }

    [Fact]
    public async Task Automation_is_idempotent_correlates_trusted_events_and_preserves_human_triage()
    {
        const string ruleId="WIN-DEFENDER-DETECTION";
        var ids=new List<int>();
        AutomationRule original;
        using(var scope=factory.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            original=await db.AutomationRules.AsNoTracking().SingleAsync(x=>x.Id==ruleId);
            var p=await db.AutomationRules.SingleAsync(x=>x.Id==ruleId);
            p.Mode="AutoPromote";p.ApprovedById=actorId;p.OwnerId=actorId;p.EffectiveFrom=DateTime.UtcNow.AddMinutes(-1);p.Version++;
            await db.SaveChangesAsync();
        }
        async Task<int> Add(string host, bool trusted=true, bool rightProvider=true) {
            using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var a=new Alert{Title="Automation isolated test",Source=AlertSource.WindowsEvent,SourceRuleId=ruleId,Severity="High",Status=AlertStatus.New,DetectedAt=DateTime.UtcNow,ReceivedAt=DateTime.UtcNow};
            db.Alerts.Add(a);await db.SaveChangesAsync();ids.Add(a.Id);
            if(trusted){db.WindowsEvents.Add(new(){AlertId=a.Id,Fingerprint=Guid.NewGuid().ToString("N"),Machine=host,Channel="Microsoft-Windows-Windows Defender/Operational",Provider=rightProvider?"Microsoft-Windows-Windows Defender":"Untrusted provider",EventId=1116,ReceivedAt=DateTime.UtcNow,RawXml="<Event/>"});await db.SaveChangesAsync();}return a.Id;
        }
        async Task Run(int id){using var scope=factory.Services.CreateScope();await scope.ServiceProvider.GetRequiredService<IncidentPlatform.Api.Services.AutomationProcessor>().ProcessAsync(ruleId,id,default);}
        try {
            var first=await Add("isolated-host");
            await Task.WhenAll(Run(first),Run(first));
            var second=await Add("isolated-host");await Run(second);
            var spoofed=await Add("isolated-host",false);await Run(spoofed);
            var wrong=await Add("isolated-host",true,false);await Run(wrong);
            int incidentId;
            using(var scope=factory.Services.CreateScope()) {
                var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var rows=await db.AutomationDecisions.Where(x=>ids.Contains(x.AlertId)).ToListAsync();Assert.Equal(4,rows.Count);
                // Untrusted alerts are recorded as NotEligible so the worker stops reselecting them, and stay New for humans.
                foreach(var rejectedId in new[]{spoofed,wrong}) {
                    var row=rows.Single(x=>x.AlertId==rejectedId);Assert.Equal("NotEligible",row.Outcome);Assert.Null(row.IncidentId);
                    Assert.Equal(AlertStatus.New,(await db.Alerts.FindAsync(rejectedId))!.Status);
                }
                var linked=rows.Where(x=>x.IncidentId!=null).ToList();Assert.Equal(2,linked.Count);
                Assert.Equal(linked[0].IncidentId,linked[1].IncidentId);incidentId=linked[0].IncidentId!.Value;
                Assert.Single(rows,x=>x.Outcome=="IncidentCreated");Assert.Single(rows,x=>x.Outcome=="LinkedToIncident");
                Assert.True(await db.IncidentTimelineEvents.AnyAsync(x=>x.IncidentId==incidentId && x.IsSystemGenerated));
                var incident=await db.Incidents.FindAsync(incidentId);incident!.Status=IncidentStatus.Closed;await db.SaveChangesAsync();
            }
            var afterClosed=await Add("isolated-host");await Run(afterClosed);
            using(var scope=factory.Services.CreateScope()) {
                var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
                Assert.NotEqual(incidentId,(await db.Alerts.FindAsync(afterClosed))!.IncidentId);
                var p=await db.AutomationRules.SingleAsync(x=>x.Id==ruleId);p.Mode="Observe";await db.SaveChangesAsync();
            }
            var observe=await Add("isolated-host");await Run(observe);
            using(var scope=factory.Services.CreateScope()) {
                var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();Assert.Null((await db.Alerts.FindAsync(observe))!.IncidentId);
                Assert.Equal("Observed",(await db.AutomationDecisions.SingleAsync(x=>x.AlertId==observe)).Outcome);
            }
            var rejected=await client.PutAsJsonAsync("/api/automation/rules/WIN-ACCOUNT-CREATED",new{mode="AutoPromote",version=1,ownerId=actorId,correlationMinutes=60});
            Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);
            var conflict=await client.PutAsJsonAsync("/api/automation/rules/"+ruleId,new{mode="Observe",version=-1,ownerId=actorId,correlationMinutes=60});Assert.Equal(HttpStatusCode.Conflict,conflict.StatusCode);
            var rules=await client.GetAsync("/api/automation/rules");rules.EnsureSuccessStatusCode();
            var coverage=await client.GetFromJsonAsync<JsonElement>("/api/automation/coverage");Assert.Equal("Not assessed",coverage.GetProperty("benchmark").GetProperty("status").GetString());
            using var anonymous=factory.CreateClient();Assert.Equal(HttpStatusCode.Unauthorized,(await anonymous.GetAsync("/api/automation/rules")).StatusCode);
        } finally {
            using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.WindowsEvents.Where(x=>x.AlertId!=null && ids.Contains(x.AlertId.Value)).ExecuteDeleteAsync();
            await db.AutomationDecisions.Where(x=>ids.Contains(x.AlertId)).ExecuteDeleteAsync();
            await db.Alerts.Where(x=>ids.Contains(x.Id)).ExecuteDeleteAsync();
            var incidentIds=await db.Incidents.Where(x=>x.CreatedById==actorId).Select(x=>x.Id.ToString()).ToListAsync();
            await db.AuditLogs.Where(x=>x.ActorEmail=="system:incident-automation" && x.EntityType=="Incident" && incidentIds.Contains(x.EntityId!)).ExecuteDeleteAsync();
            var textIds=ids.Select(x=>x.ToString()).ToArray();await db.AuditLogs.Where(x=>x.ActorEmail=="system:incident-automation" && textIds.Contains(x.EntityId!)).ExecuteDeleteAsync();
            var p=await db.AutomationRules.SingleAsync(x=>x.Id==ruleId);db.Entry(p).CurrentValues.SetValues(original);await db.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task Soc_views_aggregate_real_links_filter_events_and_expose_response_tasks()
    {
        var created=await client.PostAsJsonAsync("/api/incidents",new IncidentCreateRequest{Title="SOC isolated overview",Description="Scope test",Severity=IncidentSeverity.High,Category=IncidentCategory.Malware,Priority=IncidentPriority.High,Source=IncidentSource.Manual});
        created.EnsureSuccessStatusCode();var incident=(await created.Content.ReadFromJsonAsync<IncidentDetailResponse>())!;
        int assetId=0,techniqueId=0;long eventId=0;
        var channel="SocTest-"+Guid.NewGuid().ToString("N");
        try {
            using(var scope=factory.Services.CreateScope()){
                var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var asset=new Asset{Name="Isolated SOC host",Type=AssetType.Workstation,CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow};db.Assets.Add(asset);await db.SaveChangesAsync();assetId=asset.Id;
                techniqueId=await db.MitreTechniques.Where(x=>!x.IsDeprecated).Select(x=>x.Id).FirstAsync();
                db.IncidentAssets.Add(new(){IncidentId=incident.Id,AssetId=assetId,AddedById=actorId,AddedAt=DateTime.UtcNow});
                db.IncidentMitreTechniques.Add(new(){IncidentId=incident.Id,MitreTechniqueId=techniqueId,AddedById=actorId,AddedAt=DateTime.UtcNow});
                db.ResponseActions.Add(new(){IncidentId=incident.Id,ActionType=ResponseActionType.Other,Description="Isolated response task",Status=ResponseActionStatus.Planned,PerformedById=actorId});
                var e=new WindowsEvent{Fingerprint=Guid.NewGuid().ToString("N"),Machine="isolated-soc",Channel=channel,Provider="SOC Provider",EventId=42,ReceivedAt=DateTime.UtcNow,Message="exact search needle",RawXml="<Event/>"};db.WindowsEvents.Add(e);await db.SaveChangesAsync();eventId=e.Id;
            }
            var overview=await client.GetFromJsonAsync<JsonElement>("/api/soc/overview?hours=24");
            Assert.Contains(overview.GetProperty("latest").EnumerateArray(),x=>x.GetProperty("id").GetInt32()==incident.Id);
            Assert.Contains(overview.GetProperty("topHosts").EnumerateArray(),x=>x.GetProperty("id").GetInt32()==assetId && x.GetProperty("count").GetInt32()==1);
            var matrix=await client.GetFromJsonAsync<JsonElement>("/api/soc/attacks?hours=24");
            Assert.Contains(matrix.GetProperty("counts").EnumerateArray(),x=>x.GetProperty("id").GetInt32()==techniqueId && x.GetProperty("count").GetInt32()>=1);
            var linked=await client.GetFromJsonAsync<JsonElement>($"/api/soc/techniques/{techniqueId}/incidents?hours=24");Assert.Contains(linked.EnumerateArray(),x=>x.GetProperty("id").GetInt32()==incident.Id);
            var tasks=await client.GetFromJsonAsync<JsonElement>("/api/soc/tasks?status=0");Assert.Contains(tasks.GetProperty("items").EnumerateArray(),x=>x.GetProperty("incidentId").GetInt32()==incident.Id);
            var analytics=await client.GetFromJsonAsync<JsonElement>($"/api/soc/analytics?minutes=60&channel={channel}&search=needle");
            Assert.Equal(1,analytics.GetProperty("total").GetInt32());Assert.Equal(eventId,analytics.GetProperty("items")[0].GetProperty("id").GetInt64());
            Assert.Equal(1,analytics.GetProperty("series").EnumerateArray().Sum(x=>x.GetProperty("count").GetInt32()));
            var empty=await client.GetFromJsonAsync<JsonElement>($"/api/soc/analytics?channel={channel}&search=nomatch");Assert.Equal(0,empty.GetProperty("total").GetInt32());
            Assert.Equal(HttpStatusCode.BadRequest,(await client.GetAsync("/api/soc/overview?hours=0")).StatusCode);
        }finally{
            using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.WindowsEvents.Where(x=>x.Id==eventId).ExecuteDeleteAsync();await db.IncidentAssets.Where(x=>x.AssetId==assetId).ExecuteDeleteAsync();await db.Assets.Where(x=>x.Id==assetId).ExecuteDeleteAsync();
        }
    }

    private sealed class FailingAudit : IAuditContext
    {
        public bool IsActive => true;
        public int? ActorUserId { get; set; }
        public string? ActorEmail { get; set; }
        public AuditLog Create(string action, string? entityType = null, string? entityId = null,
            AuditOutcome outcome = AuditOutcome.Success, string? details = null) => throw new InvalidOperationException("Audit unavailable");
    }

    [Fact]
    public async Task Dashboard_executes_only_SQL_aggregates_without_materializing_entities()
    {
        using var scope = factory.Services.CreateScope();
        var capture = new DashboardSqlCapture();
        var options = new DbContextOptionsBuilder<AppDbContext>(scope.ServiceProvider.GetRequiredService<DbContextOptions<AppDbContext>>())
            .AddInterceptors(capture).Options;
        await using var db = new AppDbContext(options);
        var service = new IncidentPlatform.Api.Services.DashboardService(db, new DashboardUser(actorId));
        await service.SummaryAsync(default);
        Assert.NotEmpty(capture.Commands);
        Assert.All(capture.Commands, sql => Assert.Contains("COUNT(", sql.ToUpperInvariant()));
        var grouped = new Func<Task>[] {
            async () => { await service.BySeverityAsync(default); },
            async () => { await service.ByStatusAsync(default); },
            async () => { await service.ByCategoryAsync(default); },
            async () => { await service.OverTimeAsync(30, "day", default); },
            async () => { await service.OverTimeAsync(30, "week", default); },
            async () => { await service.TopIocTypesAsync(default); },
            async () => { await service.TopTechniquesAsync(10, default); }
        };
        foreach (var run in grouped)
        {
            capture.Commands.Clear();
            await run();
            var sql = Assert.Single(capture.Commands).ToUpperInvariant();
            Assert.Contains("GROUP BY", sql);
            Assert.Contains("COUNT(", sql);
        }
        capture.Commands.Clear();
        await service.MetricsAsync(30, default);
        Assert.Contains(capture.Commands, sql => sql.Contains("AVG(", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(capture.Commands, sql => sql.Contains("COUNT(", StringComparison.OrdinalIgnoreCase));
        Assert.All(capture.Commands, sql => Assert.True(sql.Contains("AVG(", StringComparison.OrdinalIgnoreCase) || sql.Contains("COUNT(", StringComparison.OrdinalIgnoreCase), sql));
        Assert.Empty(db.ChangeTracker.Entries());
    }

    private sealed class DashboardUser(int id) : ICurrentUser
    {
        public int Id => id;
        public IReadOnlyList<string> Roles => [RoleNames.Admin];
        public bool IsInRole(string role) => Roles.Contains(role);
    }
    private sealed class DashboardSqlCapture : Microsoft.EntityFrameworkCore.Diagnostics.DbCommandInterceptor
    {
        public List<string> Commands { get; } = [];
        public override ValueTask<Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command, Microsoft.EntityFrameworkCore.Diagnostics.CommandEventData eventData,
            Microsoft.EntityFrameworkCore.Diagnostics.InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Commands.Add(command.CommandText);
            return ValueTask.FromResult(result);
        }
    }

    [Fact]
    public async Task Dashboard_aggregates_real_mysql_milestones_and_fills_empty_time_buckets()
    {
        var before = (await client.GetFromJsonAsync<DashboardMetrics>("/api/dashboard/metrics"))!;
        var summaryBefore = (await client.GetFromJsonAsync<DashboardSummary>("/api/dashboard/summary"))!;
        if (before.DetectionSampleSize == 0) Assert.Null(before.MeanTimeToDetectMinutes);
        if (before.ContainmentSampleSize == 0) Assert.Null(before.MeanTimeToContainMinutes);
        if (before.ResolutionSampleSize == 0) Assert.Null(before.MeanTimeToResolveMinutes);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var now = DateTime.UtcNow;
            db.Incidents.AddRange(
                new Incident { IncidentNumber = "T-" + Guid.NewGuid().ToString("N")[..16], Title = "Metrics", Description = "test",
                    CreatedById = actorId, AssignedToId = actorId, CreatedAt = now, UpdatedAt = now,
                    Status = IncidentStatus.Investigating, Severity = IncidentSeverity.Critical,
                    OccurredAt = now.AddMinutes(-70), DetectedAt = now.AddMinutes(-60),
                    ContainedAt = now.AddMinutes(-30), ResolvedAt = now },
                new Incident { IncidentNumber = "T-" + Guid.NewGuid().ToString("N")[..16], Title = "Unknown milestones", Description = "test",
                    CreatedById = actorId, CreatedAt = now, UpdatedAt = now, Status = IncidentStatus.Closed },
                new Incident { IncidentNumber = "T-" + Guid.NewGuid().ToString("N")[..16], Title = "Invalid historical milestones", Description = "test",
                    CreatedById = actorId, CreatedAt = now, UpdatedAt = now, Status = IncidentStatus.Closed,
                    OccurredAt = now, DetectedAt = now.AddMinutes(-1), ContainedAt = now.AddMinutes(-2), ResolvedAt = now.AddMinutes(-2) });
            await db.SaveChangesAsync();
        }
        var metrics = (await client.GetFromJsonAsync<DashboardMetrics>("/api/dashboard/metrics"))!;
        Assert.Equal(before.SampleSize + 3, metrics.SampleSize);
        Assert.Equal(before.DetectionSampleSize + 1, metrics.DetectionSampleSize);
        Assert.Equal(((before.MeanTimeToDetectMinutes ?? 0) * before.DetectionSampleSize + 10) / metrics.DetectionSampleSize,
            metrics.MeanTimeToDetectMinutes!.Value, 3);
        Assert.Equal(((before.MeanTimeToContainMinutes ?? 0) * before.ContainmentSampleSize + 30) / metrics.ContainmentSampleSize,
            metrics.MeanTimeToContainMinutes!.Value, 3);
        Assert.Equal(((before.MeanTimeToResolveMinutes ?? 0) * before.ResolutionSampleSize + 60) / metrics.ResolutionSampleSize,
            metrics.MeanTimeToResolveMinutes!.Value, 3);
        var summary = (await client.GetFromJsonAsync<DashboardSummary>("/api/dashboard/summary"))!;
        Assert.Equal(summaryBefore.TotalIncidents + 3, summary.TotalIncidents);
        Assert.Equal(summaryBefore.OpenIncidents + 1, summary.OpenIncidents);
        Assert.Equal(summaryBefore.MyOpenIncidents + 1, summary.MyOpenIncidents);
        foreach (var route in new[] { "incidents-by-severity", "incidents-by-status", "incidents-by-category" })
        {
            var counts = (await client.GetFromJsonAsync<List<CountBucket>>("/api/dashboard/" + route))!;
            Assert.Equal(summary.TotalIncidents, counts.Sum(c => c.Count));
        }
        foreach (var route in new[] { "top-ioc-types", "top-mitre-techniques" })
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/dashboard/" + route)).StatusCode);
        var days = (await client.GetFromJsonAsync<List<TimeBucket>>("/api/dashboard/incidents-over-time?days=7"))!;
        Assert.Equal(7, days.Count);
        Assert.True(days[^1].Count >= 3);
        var weeks = (await client.GetFromJsonAsync<List<TimeBucket>>("/api/dashboard/incidents-over-time?days=30&interval=week"))!;
        Assert.Equal(5, weeks.Count);
        foreach (var route in new[] { "incidents-over-time?days=366", "incidents-over-time?interval=bad", "metrics?periodDays=0", "top-mitre-techniques?limit=101" })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/dashboard/" + route)).StatusCode);
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/dashboard/summary")).StatusCode);
    }

    [Fact]
    public async Task Login_rate_limit_normalizes_email_and_returns_problem_details_and_retry_after()
    {
        using var anonymous = factory.CreateClient();
        // Initialization already consumed one of this account's five permits.
        for (var n = 0; n < 4; n++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync("/api/auth/login",
                new LoginRequest { Email = email.ToUpperInvariant(), Password = "wrong" })).StatusCode);
        var limited = await anonymous.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = Password });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", limited.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task Health_readiness_and_security_headers_are_observable_without_dependency_details()
    {
        var ready = await client.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal("Healthy", await ready.Content.ReadAsStringAsync());
        using var unavailable = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.PostConfigure<HealthCheckServiceOptions>(options =>
            {
                options.Registrations.Clear();
                options.Registrations.Add(new HealthCheckRegistration("mysql", new UnavailableDatabase(), null, ["ready"]));
            })));
        using var http = unavailable.CreateClient();
        var failed = await http.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
        Assert.Equal("Unhealthy", await failed.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health")).StatusCode);
        foreach (var path in new[] { "/health", "/api/users", "/api/unknown-route" })
        {
            var response = await http.GetAsync(path);
            Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
            Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        }
    }

    private sealed class UnavailableDatabase : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
            => Task.FromResult(HealthCheckResult.Unhealthy("private database error"));
    }
}
