using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;
public class AssessmentSelectionTests : IClassFixture<TestApiFactory>
{
 private readonly TestApiFactory factory;
 public AssessmentSelectionTests(TestApiFactory factory)=>this.factory=factory;
 [Fact]
 public async Task Selection_persists_in_original_model_and_denials_are_audited()
 {
  var handler=new SelectionHandler();
  using var app=factory.WithWebHostBuilder(b=>{
   b.ConfigureAppConfiguration((_,c)=>c.AddInMemoryCollection(new Dictionary<string,string?> {
    ["HexStrike:Enabled"]="true",["HexStrike:GatewayUrl"]="https://127.0.0.1:9443",["HexStrike:GatewayToken"]=new string('x',32),
    ["HexStrike:Targets:0:Id"]="selection-fixture",["HexStrike:Targets:0:Name"]="Selection fixture",["HexStrike:Targets:0:Ip"]="192.168.207.129",["HexStrike:Targets:0:Approved"]="true"
   }));
   b.ConfigureServices(s=>s.AddHttpClient("AssessmentGateway").ConfigurePrimaryHttpMessageHandler(()=>handler));
  });
  using var scope=app.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
  var email=$"selection-{Guid.NewGuid():N}@example.com";
  var actor=new User{Email=email,FullName="Selection test",PasswordHash=scope.ServiceProvider.GetRequiredService<IPasswordHasher>().Hash("Password123!"),IsActive=true,CreatedAt=DateTime.UtcNow,UpdatedAt=DateTime.UtcNow};
  db.Users.Add(actor);await db.SaveChangesAsync();
  var role=await db.Roles.SingleAsync(r=>r.Name==RoleNames.Admin);db.UserRoles.Add(new(){UserId=actor.Id,RoleId=role.Id,AssignedById=actor.Id,AssignedAt=DateTime.UtcNow});await db.SaveChangesAsync();
  using var client=app.CreateClient();
  try {
   var login=await client.PostAsJsonAsync("/api/auth/login",new LoginRequest{Email=email,Password="Password123!"});login.EnsureSuccessStatusCode();
   client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer",(await login.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken);
   object Body(string target="selection-fixture",string manifest="fixture")=>new{targetId=target,categories=new[]{"Web"},selectedTools=new[]{"nuclei_scan"},manifestId=manifest,confirmed=false,webPort=8080,webHttps=false};
   var beforeAlerts=await db.Alerts.CountAsync();var beforeIncidents=await db.Incidents.CountAsync();
   var created=await client.PostAsJsonAsync("/api/assessments/scan",Body());created.EnsureSuccessStatusCode();Assert.Equal(HttpStatusCode.Accepted,created.StatusCode);
   var row=await created.Content.ReadFromJsonAsync<SecurityAssessment>();Assert.NotNull(row);
   var stored=await db.SecurityAssessments.AsNoTracking().SingleAsync(r=>r.Id==row.Id);
   Assert.Equal("selected-tools",stored.Profile);Assert.Equal("Pending",stored.Status);
   using var saved=JsonDocument.Parse(stored.RequestJson!);Assert.Equal("nuclei_scan",saved.RootElement.GetProperty("selectedTools")[0].GetString());
   var calls=handler.Calls;
   var denied=await client.PostAsJsonAsync("/api/assessments/scan",Body("unapproved-selection-fixture"));
   Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);Assert.Equal(calls,handler.Calls);
   var envelope=await denied.Content.ReadFromJsonAsync<JsonElement>();Assert.True(envelope.TryGetProperty("traceId",out _));Assert.True(envelope.TryGetProperty("error",out _));
   Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsJsonAsync("/api/assessments/scan",Body(manifest:"changed"))).StatusCode);
   Assert.Equal(HttpStatusCode.BadRequest,(await client.PostAsJsonAsync("/api/assessments",new{targetId="selection-fixture",profile="vulnerability-checks"})).StatusCode);
   Assert.True(await db.AuditLogs.AnyAsync(a=>a.Action=="ASSESSMENT_REJECTED"&&a.Outcome==AuditOutcome.Denied&&a.EntityId=="unapproved-selection-fixture"));
   Assert.Equal(beforeAlerts,await db.Alerts.CountAsync());Assert.Equal(beforeIncidents,await db.Incidents.CountAsync());
  } finally {
   await db.SecurityAssessments.Where(a=>a.RequestedById==actor.Id).ExecuteDeleteAsync();
   await db.RefreshTokens.Where(t=>t.UserId==actor.Id).ExecuteDeleteAsync();
   await db.UserRoles.Where(r=>r.UserId==actor.Id).ExecuteDeleteAsync();
   await db.AuditLogs.Where(a=>a.ActorUserId==actor.Id||a.ActorEmail==email||a.EntityId=="unapproved-selection-fixture"||a.EntityId=="selection-fixture").ExecuteDeleteAsync();
   await db.Users.Where(u=>u.Id==actor.Id).ExecuteDeleteAsync();
  }
 }
 private sealed class SelectionHandler:HttpMessageHandler
 {
  public int Calls;
  protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
  {
   Calls++;Assert.Equal("/v1/selection",request.RequestUri!.AbsolutePath);
   var value=await request.Content!.ReadFromJsonAsync<JsonElement>(ct);
   return value.GetProperty("manifestId").GetString()=="fixture" ? new(HttpStatusCode.OK){Content=JsonContent.Create(value)} : new(HttpStatusCode.BadRequest);
  }
 }
}
