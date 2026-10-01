using System.Text.Json;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Controllers;
using IncidentPlatform.Api.DTOs.Alerts;
using Microsoft.AspNetCore.Mvc;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using IncidentPlatform.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;

public class SigmaDetectionTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory factory;
    public SigmaDetectionTests(TestApiFactory factory)=>this.factory=factory;
    private static JsonElement[] Fixtures()=>JsonSerializer.Deserialize<JsonElement[]>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory,"Fixtures","sigma-conditions.json")))!;
    private static DetectionRule Rule(JsonElement tree)=>new(){ExternalRuleId=Guid.NewGuid().ToString(),Title="Isolated Sigma fixture",Severity="High",CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow,
        DefinitionJson=JsonSerializer.Serialize(new{compilerVersion=1,status="Compiled",logsource=new{product="windows",service="security"},compiled=tree,tags=new[]{"attack.t1110"},sourceSha256=new string('a',64)})};
    private static WindowsEvent Event(string fp)=>new(){Fingerprint=fp,Channel="Security",Provider="Microsoft-Windows-Security-Auditing",Machine="SIGMA-FIXTURE",EventId=4625,ReceivedAt=DateTime.UtcNow,
        RawXml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData><Data Name='TargetUserName'>admin1</Data><Data Name='SubjectUserName'>admin1</Data><Data Name='IpAddress'>192.168.207.129</Data><Data Name='Encoded'>aGVsbG8=</Data></EventData></Event>"};
    [Fact]
    public void Xml_payload_channel_and_execution_fields_are_preserved()
    {
        var e=Event("mapping");e.Channel="System";
        e.RawXml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Execution ProcessID='0' /></System><UserData><LogFileCleared xmlns='EventLog'><Channel>Security</Channel></LogFileCleared></UserData></Event>";
        var fields=SigmaConditions.Fields(e);
        Assert.Equal("Security",fields["Channel"].Single());Assert.Equal("System",fields["EventChannel"].Single());Assert.Equal("0",fields["ProcessId"].Single());
    }
    [Fact]
    public void Official_pysigma_condition_trees_match_expected_event_and_case_semantics()
    {
        var e=Event("unused");var fields=SigmaConditions.Fields(e);
        foreach(var fixture in Fixtures())
        {
            var rule=Rule(fixture.GetProperty("compiled"));Assert.Null(SigmaConditions.Unsupported(rule));
            Assert.Equal(fixture.GetProperty("name").GetString()!="case",SigmaConditions.Matches(rule,e,fields));
        }
        var contains=Rule(Fixtures()[0].GetProperty("compiled"));fields["TargetUserName"]=["guest"];
        Assert.False(SigmaConditions.Matches(contains,e,fields));
        e.Channel="System";Assert.False(SigmaConditions.Matches(contains,e,fields));
    }
    [Fact]
    public void Unknown_sources_and_unknown_operators_cannot_be_enabled()
    {
        var rule=Rule(Fixtures()[0].GetProperty("compiled"));rule.DefinitionJson=rule.DefinitionJson.Replace("security","unknown-service");
        Assert.NotNull(SigmaConditions.Unsupported(rule));
        rule=Rule(JsonSerializer.Deserialize<JsonElement>("{\"op\":\"execute\"}"));Assert.NotNull(SigmaConditions.Unsupported(rule));
    }
    [Fact]
    public void Xml_entities_are_never_resolved()
    {
        var e=Event("unused");e.RawXml="<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///secret'>]><x>&y;</x>";
        Assert.Throws<System.Xml.XmlException>(()=>SigmaConditions.Fields(e));
    }
    [Fact]
    public async Task Disabled_rules_do_not_alert_enabled_rules_use_existing_alerts_and_replay_deduplicates()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var rule=Rule(Fixtures()[0].GetProperty("compiled"));var second=Rule(Fixtures()[1].GetProperty("compiled"));
        var prefix=Guid.NewGuid().ToString("N");var a=Event(prefix+"a");var b=Event(prefix+"b");
        db.DetectionRules.AddRange(rule,second);await db.SaveChangesAsync();
        var incidents=await db.Incidents.CountAsync();int? promotedId=null;
        var actor=new Actor(await db.Users.Select(u=>u.Id).FirstAsync());
        var reference=await db.MitreTechniques.FirstAsync();
        rule.DefinitionJson=rule.DefinitionJson.Replace("attack.t1110","attack."+reference.TechniqueId.ToLowerInvariant());
        await db.SaveChangesAsync();
        try
        {
            await using(var tx=await db.Database.BeginTransactionAsync())
            {Assert.Equal(1,await WindowsEventWriter.Store(db,[a],"fixture",default));await db.SaveChangesAsync();await tx.CommitAsync();}
            Assert.Null(a.AlertId);
            rule.Enabled=true;second.Enabled=true;await db.SaveChangesAsync();
            await using(var tx=await db.Database.BeginTransactionAsync())
            {Assert.Equal(1,await WindowsEventWriter.Store(db,[b],"fixture",default));await db.SaveChangesAsync();await tx.CommitAsync();}
            Assert.NotNull(b.AlertId);
            var alerts=await db.Alerts.Where(x=>x.SourceRuleId=="SIGMA-"+rule.ExternalRuleId||x.SourceRuleId=="SIGMA-"+second.ExternalRuleId).ToListAsync();
            Assert.Equal(2,alerts.Count);Assert.All(alerts,x=>{Assert.Equal(AlertSource.WindowsEvent,x.Source);Assert.Null(x.IncidentId);Assert.Contains(b.Fingerprint,x.RawPayload);});
            await using(var tx=await db.Database.BeginTransactionAsync())
            {Assert.Equal(0,await WindowsEventWriter.Store(db,[Event(b.Fingerprint)],"fixture",default));await db.SaveChangesAsync();await tx.CommitAsync();}
            Assert.Equal(incidents,await db.Incidents.CountAsync());
            var selected=alerts.Single(x=>x.SourceRuleId=="SIGMA-"+rule.ExternalRuleId);
            var promoted=await new AlertService(db,actor).PromoteAsync(selected.Id,new PromoteAlertRequest{Title="Isolated Sigma promotion",Severity=IncidentSeverity.High,Priority=IncidentPriority.High,Category=IncidentCategory.Other});
            promotedId=promoted.Id;
            var link=await db.IncidentMitreTechniques.SingleAsync(x=>x.IncidentId==promotedId && x.MitreTechniqueId==reference.Id);
            Assert.Contains("Documentation mapping only",link.Notes);
            Assert.Equal(AlertStatus.Promoted,selected.Status);
        }
        finally
        {
            await db.WindowsEvents.Where(x=>x.Fingerprint.StartsWith(prefix)).ExecuteDeleteAsync();
            await db.Alerts.Where(x=>x.SourceRuleId=="SIGMA-"+rule.ExternalRuleId||x.SourceRuleId=="SIGMA-"+second.ExternalRuleId).ExecuteDeleteAsync();
            if(promotedId.HasValue)await db.Incidents.Where(x=>x.Id==promotedId).ExecuteDeleteAsync();
            await db.DetectionRules.Where(x=>x.Id==rule.Id||x.Id==second.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Imported_policy_promotes_real_matching_evidence_and_groups_same_host_only_once()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var admin=await db.Users.FirstAsync(u=>u.IsActive && u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin));
        var rule=Rule(Fixtures()[0].GetProperty("compiled"));db.DetectionRules.Add(rule);await db.SaveChangesAsync();await db.Entry(rule).ReloadAsync();
        var controller=new DetectionRulesController(db,new Actor(admin.Id));
        var policyId="SIGMA-"+rule.ExternalRuleId;var prefix=Guid.NewGuid().ToString("N");
        var incidentIds=new List<int>();
        try
        {
            Assert.IsType<OkObjectResult>(await controller.SetEnabled(rule.Id,new(true,rule.UpdatedAt,true,"AutoPromote",admin.Id),default));
            foreach(var suffix in new[]{"a","b"})
            {
                var e=Event(prefix+suffix);
                await using(var tx=await db.Database.BeginTransactionAsync())
                {await WindowsEventWriter.Store(db,[e],"isolated fixture",default);await db.SaveChangesAsync();await tx.CommitAsync();}
                var alert=await db.Alerts.SingleAsync(a=>a.DeduplicationKey=="sigma:"+rule.ExternalRuleId+":"+e.Fingerprint);
                await new AutomationProcessor(db).ProcessAsync(policyId,alert.Id,default);
                Assert.Equal(AlertStatus.Promoted,alert.Status);Assert.NotNull(alert.IncidentId);incidentIds.Add(alert.IncidentId!.Value);
                await new AutomationProcessor(db).ProcessAsync(policyId,alert.Id,default);
            }
            Assert.Single(incidentIds.Distinct());
            Assert.Equal(2,await db.AutomationDecisions.CountAsync(d=>d.RuleId==policyId));
            var preview=Assert.IsType<OkObjectResult>(await controller.Preview(rule.Id));
            Assert.True(JsonSerializer.SerializeToElement(preview.Value).GetProperty("matched").GetInt32()>=2);
        }
        finally
        {
            await db.AutomationDecisions.Where(d=>d.RuleId==policyId).ExecuteDeleteAsync();
            await db.WindowsEvents.Where(e=>e.Fingerprint.StartsWith(prefix)).ExecuteDeleteAsync();
            await db.Alerts.Where(a=>a.SourceRuleId==policyId).ExecuteDeleteAsync();
            await db.Incidents.Where(i=>incidentIds.Contains(i.Id)).ExecuteDeleteAsync();
            await db.AutomationRules.Where(p=>p.Id==policyId).ExecuteDeleteAsync();
            await db.DetectionRules.Where(r=>r.Id==rule.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Historical_review_requires_confirmation_and_reuses_evidence_without_duplicate_alerts()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var admin=await db.Users.FirstAsync(u=>u.IsActive && u.UserRoles.Any(r=>r.Role.Name==RoleNames.Admin));
        var rule=Rule(Fixtures()[0].GetProperty("compiled"));db.DetectionRules.Add(rule);
        var e=Event(Guid.NewGuid().ToString("N"));e.ReceivedAt=DateTime.UtcNow.AddDays(-2);e.TimeCreated=e.ReceivedAt;db.WindowsEvents.Add(e);await db.SaveChangesAsync();await db.Entry(rule).ReloadAsync();
        var controller=new DetectionRulesController(db,new Actor(admin.Id));var policyId="SIGMA-"+rule.ExternalRuleId;int? incidentId=null;
        try
        {
            Assert.IsType<BadRequestObjectResult>(await controller.Reevaluate(rule.Id,new([e.Id],rule.UpdatedAt,true),default));
            Assert.IsType<OkObjectResult>(await controller.SetEnabled(rule.Id,new(true,rule.UpdatedAt,true,"AutoPromote",admin.Id),default));
            Assert.IsType<BadRequestObjectResult>(await controller.Reevaluate(rule.Id,new([e.Id],rule.UpdatedAt,false),default));
            Assert.IsType<ConflictObjectResult>(await controller.Reevaluate(rule.Id,new([e.Id],DateTime.MinValue,true),default));
            Assert.IsType<BadRequestObjectResult>(await controller.Reevaluate(rule.Id,new([long.MaxValue],rule.UpdatedAt,true),default));
            var first=Assert.IsType<OkObjectResult>(await controller.Reevaluate(rule.Id,new([e.Id],rule.UpdatedAt,true),default));
            Assert.Equal(1,Assert.IsType<WindowsEventWriter.ReevaluationResult>(first.Value).Created);
            var second=Assert.IsType<OkObjectResult>(await controller.Reevaluate(rule.Id,new([e.Id],rule.UpdatedAt,true),default));
            Assert.Equal(1,Assert.IsType<WindowsEventWriter.ReevaluationResult>(second.Value).Duplicates);
            var alert=await db.Alerts.SingleAsync(a=>a.SourceRuleId==policyId);
            Assert.Equal(e.TimeCreated,alert.DetectedAt);Assert.Contains("HistoricalReview",alert.RawPayload);
            await new AutomationProcessor(db).ProcessAsync(policyId,alert.Id,default);
            Assert.Equal(AlertStatus.Promoted,alert.Status);incidentId=alert.IncidentId;Assert.NotNull(incidentId);
            await db.Entry(e).ReloadAsync();Assert.True(e.ReceivedAt<DateTime.UtcNow.AddDays(-1));
        }
        finally
        {
            await db.AutomationDecisions.Where(d=>d.RuleId==policyId).ExecuteDeleteAsync();
            await db.WindowsEvents.Where(x=>x.Id==e.Id).ExecuteDeleteAsync();await db.Alerts.Where(a=>a.SourceRuleId==policyId).ExecuteDeleteAsync();
            if(incidentId.HasValue)await db.Incidents.Where(i=>i.Id==incidentId).ExecuteDeleteAsync();
            await db.AutomationRules.Where(p=>p.Id==policyId).ExecuteDeleteAsync();await db.DetectionRules.Where(r=>r.Id==rule.Id).ExecuteDeleteAsync();
        }
    }

    private sealed class Actor(int id):ICurrentUser { public int Id=>id;public IReadOnlyList<string> Roles=>[RoleNames.Admin];public bool IsInRole(string role)=>Roles.Contains(role); }
    [Fact]
    public async Task Review_requires_confirmation_rejects_stale_version_and_can_disable_again()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var r=Rule(Fixtures()[0].GetProperty("compiled"));db.DetectionRules.Add(r);await db.SaveChangesAsync();await db.Entry(r).ReloadAsync();
        var controller=new DetectionRulesController(db,new Actor(await db.Users.Select(u=>u.Id).FirstAsync()));
        try {
            var stamp=r.UpdatedAt;
            Assert.IsType<BadRequestObjectResult>(await controller.SetEnabled(r.Id,new(true,stamp,false),default));
            Assert.IsType<OkObjectResult>(await controller.SetEnabled(r.Id,new(true,stamp,true),default));
            Assert.IsType<ConflictObjectResult>(await controller.SetEnabled(r.Id,new(false,stamp,false),default));
            Assert.IsType<OkObjectResult>(await controller.SetEnabled(r.Id,new(false,r.UpdatedAt,false),default));
            await db.Entry(r).ReloadAsync();Assert.False(r.Enabled);
        } finally { await db.AutomationRules.Where(p=>p.Id=="SIGMA-"+r.ExternalRuleId).ExecuteDeleteAsync();await db.DetectionRules.Where(x=>x.Id==r.Id).ExecuteDeleteAsync(); }
    }

    [Fact]
    public async Task Rule_listing_pages_keys_before_loading_large_json_definitions()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var prefix="Wide fixture "+Guid.NewGuid().ToString("N");
        var rules=Enumerable.Range(0,30).Select(i=>{var r=Rule(Fixtures()[0].GetProperty("compiled"));r.Title=prefix+" "+i.ToString("D2");r.DefinitionJson=r.DefinitionJson.Replace(new string('a',64),new string('a',60000));return r;}).ToArray();
        db.DetectionRules.AddRange(rules);await db.SaveChangesAsync();
        try {
            var controller=new DetectionRulesController(db,new Actor(await db.Users.Select(u=>u.Id).FirstAsync()));
            var response=Assert.IsType<OkObjectResult>(await controller.List(prefix,1));
            var json=JsonSerializer.SerializeToElement(response.Value);Assert.Equal(30,json.GetProperty("total").GetInt32());Assert.Equal(25,json.GetProperty("items").GetArrayLength());
        }finally { await db.DetectionRules.Where(r=>r.Title.StartsWith(prefix)).ExecuteDeleteAsync(); }
    }
}
