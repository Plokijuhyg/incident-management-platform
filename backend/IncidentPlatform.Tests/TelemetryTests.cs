using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Controllers;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;

public class TelemetryTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory factory;
    public TelemetryTests(TestApiFactory factory)=>this.factory=factory;
    private const string Token="isolated-fixture-token-not-a-real-credential-123456";
    private static string Xml(string machine,long record=1)=>$"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID><Level>0</Level><TimeCreated SystemTime='2026-01-01T00:00:00Z'/><EventRecordID>{record}</EventRecordID><Channel>Security</Channel><Computer>{machine}</Computer></System></Event>";
    [Fact]
    public async Task Authenticated_allowlisted_ingestion_reuses_alerts_and_rejects_spoofing_and_revocation()
    {
        var machine="AGENT-"+Guid.NewGuid().ToString("N")[..12].ToUpperInvariant();
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Telemetry:Enabled"]="true",["Telemetry:Agents:0:Id"]="fixture-agent",
            ["Telemetry:Agents:0:TargetId"]="fixture-target",["Telemetry:Agents:0:Enabled"]="true",
            ["Telemetry:Agents:0:TokenSha256"]=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Token))),
            ["HexStrike:Targets:0:Id"]="fixture-target",["HexStrike:Targets:0:Ip"]="192.168.207.129",
            ["HexStrike:Targets:0:Name"]="Isolated fixture",["HexStrike:Targets:0:Approved"]="true",
            ["HexStrike:Targets:0:Hostname"]=machine
        }).Build();
        using var app=factory.WithWebHostBuilder(b=>b.ConfigureServices(s=>{
            s.AddSingleton<IConfiguration>(config);
            s.AddSingleton<IStartupFilter,PeerFixture>();
        }));
        using var client=app.CreateClient(new(){BaseAddress=new Uri("https://localhost"),AllowAutoRedirect=false});
        var batch=new TelemetryBatch(Guid.NewGuid(),[new(Xml(machine),"Isolated fixture")]);
        async Task<HttpResponseMessage> Post(string peer="192.168.207.129",string token=Token,TelemetryBatch? value=null)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,"/api/telemetry/events"){Content=JsonContent.Create(value??batch)};
            request.Headers.Add("X-Agent-Id","fixture-agent");request.Headers.Add("X-Telemetry-Token",token);
            request.Headers.Add("X-Test-Peer",peer);request.Headers.Add("X-Forwarded-For","192.168.207.129");
            return await client.SendAsync(request);
        }
        using var scope=app.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var beforeIncidents=await db.Incidents.CountAsync();
        try
        {
            var first=await Post();Assert.Equal(HttpStatusCode.OK,first.StatusCode);
            var accepted=await first.Content.ReadFromJsonAsync<JsonElement>();Assert.Equal(1,accepted.GetProperty("accepted").GetInt32());
            var replay=await Post();Assert.Equal(HttpStatusCode.OK,replay.StatusCode);
            Assert.Equal(1,(await replay.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("duplicates").GetInt32());
            var row=await db.WindowsEvents.SingleAsync(e=>e.Machine==machine);
            Assert.NotNull(row.AlertId);
            Assert.Equal("WIN-ACCOUNT-CREATED",(await db.Alerts.SingleAsync(a=>a.Id==row.AlertId)).SourceRuleId);
            Assert.Equal(HttpStatusCode.Unauthorized,(await Post(token:"wrong")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden,(await Post(peer:"192.168.207.55")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest,(await Post(value:new(Guid.NewGuid(),[new(Xml("FORGED"),null)]))).StatusCode);
            // Bad second item must not partially persist the valid first item.
            Assert.Equal(HttpStatusCode.BadRequest,(await Post(value:new(Guid.NewGuid(),[new(Xml(machine,2),null),new("<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///secret'>]><x/>",null)]))).StatusCode);
            config["HexStrike:Targets:0:Approved"]="false";
            Assert.Equal(HttpStatusCode.Forbidden,(await Post()).StatusCode);
            config["HexStrike:Targets:0:Approved"]="true";config["Telemetry:Agents:0:Enabled"]="false";
            Assert.Equal(HttpStatusCode.Unauthorized,(await Post()).StatusCode);
            Assert.Equal(1,await db.WindowsEvents.CountAsync(e=>e.Machine==machine));
            Assert.Equal(beforeIncidents,await db.Incidents.CountAsync());
            Assert.True(await db.AuditLogs.CountAsync(a=>a.Action=="TELEMETRY_REJECTED" && a.EntityId=="fixture-agent")>=6);
        }
        finally
        {
            var alerts=await db.WindowsEvents.Where(e=>e.Machine==machine).Select(e=>e.AlertId).ToListAsync();
            await db.WindowsEvents.Where(e=>e.Machine==machine).ExecuteDeleteAsync();
            await db.Alerts.Where(a=>alerts.Contains(a.Id)).ExecuteDeleteAsync();
            await db.AuditLogs.Where(a=>a.EntityId=="fixture-agent" || (a.Action=="WINDOWS_RULE_ALERT_CREATED" && alerts.Select(x=>x.ToString()).Contains(a.EntityId))).ExecuteDeleteAsync();
        }
    }
    [Theory]
    [InlineData("<x/>")]
    [InlineData("<!DOCTYPE Event [<!ENTITY x SYSTEM 'file:///secret'>]><Event/>")]
    public void Xml_is_not_allowed_to_resolve_entities_or_accept_unrelated_documents(string xml)
    {
        Assert.ThrowsAny<Exception>(()=>TelemetryController.Parse(new(xml,null),"HOST"));
    }
    private sealed class PeerFixture : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)=>app=>{
            app.Use(async(context,nextMiddleware)=>{
                context.Connection.RemoteIpAddress=IPAddress.Parse(context.Request.Headers["X-Test-Peer"].FirstOrDefault()??"192.168.207.129");
                await nextMiddleware();
            });next(app);
        };
    }
}
