using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
namespace IncidentPlatform.Api.Services;
public record ApprovedAssessmentTarget(string Id,string Name,string Ip,bool Approved,string? Hostname=null);
public sealed class AssessmentGateway(IConfiguration config,IHttpClientFactory clients)
{
 public bool Enabled=>config.GetValue<bool>("HexStrike:Enabled");
 public ApprovedAssessmentTarget[] Targets=>new ApprovedLabTargets(config).All;
 public ApprovedAssessmentTarget? FindTarget(string id)=>new ApprovedLabTargets(config).Find(id);
 // Resolve a scan target from an approved configured id, or from an operator-typed private lab IP.
 // A typed IP is accepted only when it is a private/RFC1918 address, so the internet can never be a target.
 public ApprovedAssessmentTarget? ResolveTarget(string? id,string? ip)
 {
  if(!string.IsNullOrWhiteSpace(id)){var found=FindTarget(id);if(found is not null)return found;}
  var value=ip?.Trim();
  if(!string.IsNullOrEmpty(value)&&PrivateIp(value))return new ApprovedAssessmentTarget("manual:"+value,"Lab target "+value,value,true);
  return null;
 }
 public static bool PrivateIp(string value)=>IPAddress.TryParse(value,out var ip)&&ip.GetAddressBytes() is {Length:4} b&&(b[0]==10||b[0]==172&&b[1]>=16&&b[1]<=31||b[0]==192&&b[1]==168);
 public async Task<JsonElement> Send(HttpMethod method,string path,object? body,CancellationToken ct)
 {
  if(!Enabled)throw new InvalidOperationException("HexStrike integration is disabled until Laptop 2 is configured.");
  if(!Uri.TryCreate(config["HexStrike:GatewayUrl"],UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.AbsolutePath!="/"||!string.IsNullOrEmpty(uri.UserInfo)||!string.IsNullOrEmpty(uri.Query)||!string.IsNullOrEmpty(uri.Fragment)||!(PrivateIp(uri.Host)||IPAddress.TryParse(uri.Host,out var ip)&&IPAddress.IsLoopback(ip)))throw new InvalidOperationException("Configure a private HTTPS gateway address with a trusted certificate.");
  var token=config["HexStrike:GatewayToken"];
  if(string.IsNullOrEmpty(token)||token.Length<32)throw new InvalidOperationException("A gateway token of at least 32 characters is required.");
  using var message=new HttpRequestMessage(method,new Uri(uri,path));message.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);if(body is not null){message.Content=JsonContent.Create(body);await message.Content.LoadIntoBufferAsync(ct);}
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(30));
  using var response=await clients.CreateClient("AssessmentGateway").SendAsync(message,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
  response.EnsureSuccessStatusCode();await response.Content.LoadIntoBufferAsync(8*1024*1024,timeout.Token);
  using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));return json.RootElement.Clone();
 }
 public async Task<object> Capabilities(CancellationToken ct)
 {
  if(!Enabled)return new{connected=false,message="Not configured. Laptop 2 is not available yet.",profiles=Array.Empty<object>()};
  try {return await Send(HttpMethod.Get,"/v1/capabilities",null,ct);}
  catch(Exception e) when(e is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException){return new{connected=false,message="Gateway unavailable, response invalid, or configuration incomplete. No execution capability is confirmed.",profiles=Array.Empty<object>()};}
 }
}
