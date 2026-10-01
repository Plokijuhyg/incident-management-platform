using System.Net;
using System.Text.Json;
using IncidentPlatform.Api.Services;
using IncidentPlatform.Api.Controllers;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;
public class VirusTotalTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory factory;
    public VirusTotalTests(TestApiFactory factory)=>this.factory=factory;
    private sealed class Transport : HttpMessageHandler,IHttpClientFactory
    {
        public int Calls;public HttpStatusCode Status=HttpStatusCode.OK;public bool Fail;public string? Path;
        public HttpClient CreateClient(string name)=>new(this,false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Calls++;Path=request.RequestUri!.AbsoluteUri;Assert.Equal("www.virustotal.com",request.RequestUri.Host);Assert.Equal(HttpMethod.Get,request.Method);Assert.True(request.Headers.Contains("x-apikey"));
            if(Fail)throw new HttpRequestException("simulated offline");
            return Task.FromResult(new HttpResponseMessage(Status){Content=new StringContent("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":2,\"harmless\":8},\"categories\":{\"vendor\":\"test category\"}}}}")});
        }
    }
    private static VirusTotalClient Client(Transport t)=>new(t,new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["VirusTotal:ApiKey"]="isolated-fake-key"}).Build());
    [Theory]
    [InlineData("ip","192.168.207.129")][InlineData("ip","127.0.0.1")][InlineData("ip","::1")][InlineData("ip","::ffff:10.0.0.1")]
    [InlineData("domain","host.local")][InlineData("url","https://user:password@example.com/path")][InlineData("url","http://10.0.0.1/")][InlineData("hash","bad")]
    public void Private_or_invalid_indicators_are_not_submitted(string type,string value)=>Assert.Null(VirusTotalClient.Normalize(type,value));
    [Fact] public async Task Reports_are_cached_and_rate_limit_is_shared_across_indicators()
    {
        var transport=new Transport();using var client=Client(transport);
        var result=await client.Lookup(new("domain","example.com"),default);
        Assert.Equal(2,result.Malicious);Assert.Equal(10,result.Total);Assert.Contains("test category",result.Categories);
        Assert.Equal(result,await client.Lookup(new("domain","example.com"),default));Assert.Equal(1,transport.Calls);
        for(int i=0;i<3;i++)await client.Lookup(new("domain",$"test{i}.example.com"),default);
        Assert.Equal("RateLimited",(await client.Lookup(new("domain","last.example.com"),default)).Status);Assert.Equal(4,transport.Calls);
    }
    [Theory][InlineData(404,"NotFound")][InlineData(429,"RateLimited")][InlineData(500,"Unavailable")]
    public async Task Remote_failures_are_results_not_record_creation_failures(int status,string expected)
    {var t=new Transport{Status=(HttpStatusCode)status};using var client=Client(t);var result=await client.Lookup(new("domain","example.com"),default);Assert.Equal(expected,result.Status);Assert.Null(result.Malicious);}
    [Fact] public async Task Network_failure_is_best_effort_and_url_lookup_does_not_submit_a_scan()
    {
        var t=new Transport{Fail=true};using var client=Client(t);Assert.Equal("Unavailable",(await client.Lookup(new("url","https://example.com/a"),default)).Status);Assert.Contains("/api/v3/urls/",t.Path);
    }
    [Fact] public void Extraction_is_bounded_to_named_fields_and_excludes_private_targets()
    {
        var payload=JsonSerializer.Serialize(new{sourceIp="192.168.207.129",domain="example.com",description="8.8.8.8",RawXml="<Event><EventData><Data Name='IpAddress'>1.1.1.1</Data></EventData></Event>"});
        var found=IntelIndicators.FromPayload(payload).ToArray();Assert.Equal(2,found.Length);Assert.DoesNotContain(found,i=>i.Value=="8.8.8.8");
    }
    private sealed class Actor(int id):ICurrentUser {public int Id=>id;public IReadOnlyList<string> Roles=>[RoleNames.Admin];public bool IsInRole(string role)=>Roles.Contains(role);}
    [Fact] public async Task Record_binding_confirmation_persistence_and_raw_evidence_are_preserved_on_failure()
    {
        using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var actor=new Actor(await db.Users.Select(u=>u.Id).FirstAsync());
        var record=new Alert{Title="Isolated enrichment fixture",Severity="Low",RawPayload="{\"domain\":\"example.com\"}",DetectedAt=DateTime.UtcNow,ReceivedAt=DateTime.UtcNow};db.Alerts.Add(record);await db.SaveChangesAsync();await db.Entry(record).ReloadAsync();var originalEvidence=record.RawPayload;
        var transport=new Transport{Fail=true};using var client=Client(transport);var controller=new EnrichmentController(db,new AlertService(db,actor),new IncidentService(db,actor),actor,client);
        try
        {
            Assert.IsType<BadRequestObjectResult>(await controller.Enrich("alerts",record.Id,new("domain","example.com",false),default));
            Assert.IsType<BadRequestObjectResult>(await controller.Enrich("alerts",record.Id,new("domain","unrelated.com",true),default));Assert.Equal(0,transport.Calls);
            var result=Assert.IsType<OkObjectResult>(await controller.Enrich("alerts",record.Id,new("domain","example.com",true),default));Assert.Equal("Unavailable",Assert.IsType<IntelReport>(result.Value).Status);
            await db.Entry(record).ReloadAsync();Assert.Contains("Unavailable",record.EnrichmentJson);Assert.Equal(originalEvidence,record.RawPayload);Assert.Equal(AlertStatus.New,record.Status);
            await controller.Enrich("alerts",record.Id,new("domain","example.com",true),default);Assert.Equal(1,transport.Calls);
        }
        finally{await db.Alerts.Where(a=>a.Id==record.Id).ExecuteDeleteAsync();}
    }
}
