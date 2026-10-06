using System.Net;
using System.Text.Json;
using IncidentPlatform.Api.Controllers;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
namespace IncidentPlatform.Tests;
public class OllamaAnalysisTests(TestApiFactory factory):IClassFixture<TestApiFactory>
{
 sealed class Audit:IAuditContext {
  public bool IsActive=>false;public int? ActorUserId{get;set;}public string? ActorEmail{get;set;}
  public AuditLog Create(string action,string? entityType=null,string? entityId=null,AuditOutcome outcome=AuditOutcome.Success,string? details=null)=>new(){Action=action,EntityType=entityType,EntityId=entityId,Outcome=outcome,Details=details,OccurredAt=DateTime.UtcNow,IpAddress="127.0.0.1"};
 }
 sealed class Transport:HttpMessageHandler,IHttpClientFactory {
  public int Chats;public bool Fail;public bool ToolCall;public bool WrongModel;public bool Prose;public string? Prompt;public Action? OnChat;
  public HttpClient CreateClient(string name)=>new(this,false){Timeout=Timeout.InfiniteTimeSpan};
  protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r,CancellationToken ct){Assert.Equal("127.0.0.1",r.RequestUri!.Host);if(Fail)throw new HttpRequestException("private transport detail");
   if(r.RequestUri.AbsolutePath=="/api/tags")return new(HttpStatusCode.OK){Content=new StringContent("{\"models\":[{\"name\":\"llama3.1:8b\"}]}")};
   Chats++;Assert.Equal("/api/chat",r.RequestUri.AbsolutePath);Assert.Equal(HttpMethod.Post,r.Method);Prompt=await r.Content!.ReadAsStringAsync(ct);using var doc=JsonDocument.Parse(Prompt);Assert.False(doc.RootElement.TryGetProperty("tools",out _));Assert.False(doc.RootElement.GetProperty("stream").GetBoolean());
   var hasFormat=doc.RootElement.TryGetProperty("format",out var fmt);
   if(hasFormat)Assert.Equal(5,fmt.GetProperty("required").GetArrayLength());
   OnChat?.Invoke();
   string content;
   if(!hasFormat)content="## Finding Summary\nSMB on 445.\n## Exploitation Path (lab)\n1. use exploit/windows/smb/ms17_010_eternalblue\n```\nset RHOSTS 192.168.0.110\nrun\n```";
   else{var brief=fmt.GetProperty("required").EnumerateArray().ToDictionary(k=>k.GetString()!,k=>(object)(k.GetString()+" detail [1]."));content=Prose?"The host runs SSH and HTTP; review these manually.":JsonSerializer.Serialize(brief);}
   return new(HttpStatusCode.OK){Content=new StringContent(JsonSerializer.Serialize(new{model=WrongModel?"other":"llama3.1:8b",done=true,message=new{content,tool_calls=ToolCall?new[]{new{name="execute"}}:[]}}))};
  }
 }
 static IConfigurationRoot Config()=>new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Ollama:Enabled"]="true",["Ollama:Model"]="llama3.1:8b",["Lab:OllamaUrl"]="http://127.0.0.1:11434",["HexStrike:Targets:0:Id"]="analysis-fixture",["HexStrike:Targets:0:Name"]="Lab",["HexStrike:Targets:0:Ip"]="192.168.207.129",["HexStrike:Targets:0:Approved"]="true"}).Build();
 static SecurityAssessment Row()=>new(){TargetId="analysis-fixture",TargetIp="192.168.207.129",TargetName="Lab",Status="Completed",EvidenceSha256=new string('A',64),RawResponse="RAW_SECRET",ObservationsJson="[{\"kind\":\"Service\",\"port\":80,\"service\":\"http\",\"evidence\":\"DO_NOT_SEND_RAW\"}]"};
 [Fact]public void Input_is_bounded_and_excludes_raw_payload(){var row=Row();row.ObservationsJson=JsonSerializer.Serialize(Enumerable.Range(0,80).Select(i=>new{kind="Service",title=new string('x',500),evidence="DO_NOT_SEND_RAW"}));var input=OllamaAnalysis.Prepare(row);Assert.True(input.Truncated);Assert.True(input.Included<=40);Assert.True(input.Json.Length<17000);Assert.DoesNotContain("DO_NOT_SEND_RAW",input.Json);Assert.DoesNotContain("RAW_SECRET",input.Json);}
 [Theory][InlineData("http://8.8.8.8:11434")][InlineData("http://user:pass@127.0.0.1:11434")][InlineData("http://127.0.0.1:11434/other")]
 public void Endpoint_is_private_and_configuration_only(string endpoint){var config=Config();config["Lab:OllamaUrl"]=endpoint;Assert.False(new OllamaAnalysis(config,new Transport()).Configured);}
 [Fact]public async Task Network_failure_is_a_safe_result(){var row=Row();var result=await new OllamaAnalysis(Config(),new Transport{Fail=true}).Analyze(row,OllamaAnalysis.Prepare(row),default);Assert.Equal("Unavailable",result.Status);Assert.DoesNotContain("private transport",result.Error);}
 [Theory][InlineData(true,false)][InlineData(false,true)]public async Task Tool_requests_and_wrong_models_are_rejected(bool tool,bool model){var row=Row();var result=await new OllamaAnalysis(Config(),new Transport{ToolCall=tool,WrongModel=model}).Analyze(row,OllamaAnalysis.Prepare(row),default);Assert.NotEqual("Completed",result.Status);Assert.Null(result.Text);}
 [Fact]public async Task Unstructured_model_output_is_shown_not_discarded(){var row=Row();var result=await new OllamaAnalysis(Config(),new Transport{Prose=true}).Analyze(row,OllamaAnalysis.Prepare(row),default);Assert.Equal("Completed",result.Status);Assert.NotNull(result.Text);Assert.Contains("SSH",result.Text!);Assert.Contains("Unstructured",result.Text!);}
 [Fact]public async Task Offensive_mode_requests_free_form_markdown_and_is_tagged(){var row=Row();var transport=new Transport();var result=await new OllamaAnalysis(Config(),transport).Analyze(row,OllamaAnalysis.Prepare(row),default,"offensive");Assert.Equal("Completed",result.Status);Assert.Equal("offensive",result.Mode);Assert.Equal(OllamaAnalysis.OffensivePromptVersion,result.PromptVersion);Assert.Contains("isolated security lab",transport.Prompt);Assert.DoesNotContain("\"format\"",transport.Prompt);Assert.Contains("Exploitation Path (lab)",result.Text!);Assert.Contains("ms17_010_eternalblue",result.Text!);}
 [Fact]public async Task Analysis_persists_without_mutating_evidence_and_reuses_saved_report()
 {
  using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var row=Row();row.RequestedById=await db.Users.Select(u=>u.Id).FirstAsync();db.Add(row);await db.SaveChangesAsync();db.Entry(row).State=EntityState.Detached;
  var config=Config();var transport=new Transport();var controller=new AssessmentAnalysisController(db,config,new OllamaAnalysis(config,transport),new Audit()){ControllerContext=new(){HttpContext=new DefaultHttpContext()}};
  try{var result=Assert.IsType<OkObjectResult>(await controller.Analyze(row.Id,null,default));Assert.Equal("Completed",Assert.IsType<AssessmentAnalysis>(result.Value).Status);Assert.Equal(1,transport.Chats);Assert.IsType<OkObjectResult>(await controller.Analyze(row.Id,null,default));Assert.Equal(1,transport.Chats);var stored=await db.SecurityAssessments.AsNoTracking().SingleAsync(x=>x.Id==row.Id);Assert.Equal(row.RawResponse,stored.RawResponse);Assert.Equal("Completed",stored.Status);Assert.NotNull(stored.AnalysisJson);
   config["HexStrike:Targets:0:Approved"]="false";Assert.Equal(403,Assert.IsType<ObjectResult>(await controller.Analyze(row.Id,null,default)).StatusCode);Assert.Equal(1,transport.Chats);
  }finally{await db.SecurityAssessments.Where(x=>x.Id==row.Id).ExecuteDeleteAsync();}
 }
 [Fact]public async Task Revocation_during_inference_prevents_saving_the_result()
 {
  using var scope=factory.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();var row=Row();row.RequestedById=await db.Users.Select(u=>u.Id).FirstAsync();db.Add(row);await db.SaveChangesAsync();db.Entry(row).State=EntityState.Detached;
  var config=Config();var transport=new Transport{OnChat=()=>config["HexStrike:Targets:0:Approved"]="false"};var controller=new AssessmentAnalysisController(db,config,new OllamaAnalysis(config,transport),new Audit()){ControllerContext=new(){HttpContext=new DefaultHttpContext()}};
  try{Assert.Equal(403,Assert.IsType<ObjectResult>(await controller.Analyze(row.Id,null,default)).StatusCode);Assert.Null((await db.SecurityAssessments.AsNoTracking().SingleAsync(x=>x.Id==row.Id)).AnalysisJson);}finally{await db.SecurityAssessments.Where(x=>x.Id==row.Id).ExecuteDeleteAsync();}
 }
}
