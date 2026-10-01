using System.Net.Mail;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;
public class NotificationTests(TestApiFactory factory):IClassFixture<TestApiFactory>
{
 sealed class Sender:IIncidentEmailSender { public int Calls;public bool Fail; public Task Send(NotificationSettings s,string subject,string body,CancellationToken ct){Calls++;Assert.DoesNotContain("RAW_SECRET",body);if(Fail)throw new SmtpException("sensitive server detail");return Task.CompletedTask;} }
 static IConfiguration Config(DateTime since,bool enabled=true)=>new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Notifications:Enabled"]=enabled.ToString(),["Notifications:Smtp:Host"]="smtp.example.test",["Notifications:Smtp:From"]="siem@example.test",["Notifications:Smtp:To:0"]="reviewer@example.test",["Notifications:AppBaseUrl"]="https://siem.example.test",["Notifications:StartAfterUtc"]=since.ToString("O"),["Notifications:MinimumSeverity"]="High"}).Build();
 [Fact] public void Configuration_requires_explicit_cutoff_and_recipients() {Assert.False(NotificationSettings.Read(new ConfigurationBuilder().Build()).Ready);Assert.True(NotificationSettings.Read(Config(DateTime.UtcNow)).Ready);}
 [Fact] public async Task Delivery_is_deduplicated_and_failure_does_not_change_incident()
 {
  using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var since=DateTime.UtcNow.AddMinutes(5);
  var incident=new Incident{Title="Email fixture",IncidentNumber="TEST-"+Guid.NewGuid().ToString("N")[..12],Description="RAW_SECRET",Severity=IncidentSeverity.High,CreatedById=await db.Users.Select(u=>u.Id).FirstAsync(),CreatedAt=since.AddSeconds(1),UpdatedAt=since.AddSeconds(1)};
  db.Incidents.Add(incident);await db.SaveChangesAsync();var sender=new Sender{Fail=true};
  try {
   await new IncidentNotificationProcessor(db,Config(since,false),sender).Run(default);Assert.Equal(0,sender.Calls);
   var worker=new IncidentNotificationProcessor(db,Config(since),sender);await worker.Run(default);var row=await db.IncidentNotifications.SingleAsync(n=>n.IncidentId==incident.Id);Assert.Equal("Pending",row.State);Assert.Equal("SmtpException",row.LastError);Assert.Equal(IncidentStatus.New,incident.Status);
   row.NextAttemptAt=DateTime.UtcNow.AddSeconds(-1);await db.SaveChangesAsync();sender.Fail=false;await worker.Run(default);Assert.Equal("Sent",row.State);Assert.Equal(2,row.Attempts);await worker.Run(default);Assert.Equal(2,sender.Calls);
  } finally {await db.IncidentNotifications.Where(n=>n.IncidentId==incident.Id).ExecuteDeleteAsync();await db.Incidents.Where(i=>i.Id==incident.Id).ExecuteDeleteAsync();}
 }
 [Theory][InlineData("attack.t1110.001","authentication")][InlineData("attack.t1070.001","evidence")][InlineData("attack.t1543.003","service")]
 public void Guidance_uses_rule_tags_without_executing_actions(string tag,string expected){var alert=new Alert{Source=AlertSource.WindowsEvent,SourceRuleId="SIGMA-test",RawPayload=System.Text.Json.JsonSerializer.Serialize(new{tags=new[]{tag}})};Assert.Contains(expected,ResponseRecommendations.For(alert)!);}
 [Fact] public void Unknown_or_malformed_evidence_has_no_invented_guidance(){Assert.Null(ResponseRecommendations.For(new Alert{Source=AlertSource.WindowsEvent,SourceRuleId="SIGMA-test",RawPayload="bad"}));Assert.Null(ResponseRecommendations.For(new Alert{Title="brute force"}));}
}
