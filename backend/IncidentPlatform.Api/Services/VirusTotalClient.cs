using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
namespace IncidentPlatform.Api.Services;

public sealed record IntelIndicator(string Type,string Value);
public sealed record IntelReport(string Type,string Value,string Status,int? Malicious,int? Total,string[] Categories,DateTime CheckedAt,DateTime ExpiresAt,string Message);

// Singleton per API instance: serializes outbound lookups, caches across records, never queries a target.
public sealed class VirusTotalClient(IHttpClientFactory clients,IConfiguration config) : IDisposable
{
    private readonly MemoryCache cache=new(new MemoryCacheOptions{SizeLimit=2000});
    private readonly SemaphoreSlim gate=new(1,1);
    private readonly Queue<DateTime> requests=new();private DateTime day=DateTime.UtcNow.Date;private int daily;private DateTime backoff;
    public bool Configured=>!string.IsNullOrWhiteSpace(config["VirusTotal:ApiKey"]);
    public static IntelIndicator? Normalize(string type,string value)
    {
        value=value.Trim();type=type.ToLowerInvariant();if(value.Length is 0 or >2048)return null;
        if(type=="ip")return IPAddress.TryParse(value,out var ip)&&Public(ip)?new(type,ip.ToString()):null;
        if(type=="hash")return Regex.IsMatch(value,@"\A(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\z")?new(type,value.ToLowerInvariant()):null;
        if(type=="domain")
        {
            value=value.TrimEnd('.').ToLowerInvariant();
            if(value.Length>253 || !value.Contains('.') || IPAddress.TryParse(value,out _) || !Regex.IsMatch(value,@"\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z") || value.Split('.').Any(x=>x.Length is 0 or >63 || x.StartsWith('-') || x.EndsWith('-')) || new[]{".local",".localhost",".internal",".lan",".test",".invalid",".arpa"}.Any(value.EndsWith))return null;
            return new(type,value);
        }
        if(type=="url" && Uri.TryCreate(value,UriKind.Absolute,out var url) && url.Scheme is "http" or "https" && string.IsNullOrEmpty(url.UserInfo) && string.IsNullOrEmpty(url.Fragment))
        {
            if(IPAddress.TryParse(url.Host,out var host)?!Public(host):Normalize("domain",url.IdnHost) is null)return null;
            return new(type,value);
        }
        return null;
    }
    private static bool Public(IPAddress ip)
    {
        if(ip.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();if(IPAddress.IsLoopback(ip))return false;var b=ip.GetAddressBytes();
        if(b.Length==16)return (b[0]&0xe0)==0x20 && !(b[0]==0x20 && b[1]==1 && b[2]==0x0d && b[3]==0xb8);
        return b[0]!=0 && b[0]!=10 && b[0]!=127 && b[0]<224 && !(b[0]==169&&b[1]==254) && !(b[0]==172&&b[1]>=16&&b[1]<=31) && !(b[0]==192&&(b[1]==168 || b[1]==0)) && !(b[0]==100&&b[1]>=64&&b[1]<=127) && !(b[0]==198&&(b[1] is 18 or 19 || b[1]==51&&b[2]==100)) && !(b[0]==203&&b[1]==0&&b[2]==113);
    }
    public async Task<IntelReport> Lookup(IntelIndicator indicator,CancellationToken ct)
    {
        if(Normalize(indicator.Type,indicator.Value)!=indicator)throw new ArgumentException("Invalid or private indicator.");
        var key=indicator.Type+":"+indicator.Value;
        if(cache.TryGetValue<IntelReport>(key,out var cached))return cached!;
        await gate.WaitAsync(ct);
        try
        {
            if(cache.TryGetValue<IntelReport>(key,out cached))return cached!;
            var now=DateTime.UtcNow;
            IntelReport Failure(string status,string message)=>new(indicator.Type,indicator.Value,status,null,null,[],now,now.AddMinutes(1),message);
            if(!Configured)return Failure("NotConfigured","VirusTotal is not configured on the API host.");
            while(requests.TryPeek(out var old)&&old<=now.AddMinutes(-1))requests.Dequeue();
            if(day!=now.Date){day=now.Date;daily=0;}
            if(now<backoff || requests.Count>=4 || daily>=500)return Failure("RateLimited","Lookup deferred by the API quota. Retry later; the incident is unaffected.");
            var endpoint=indicator.Type switch {"ip"=>"ip_addresses/"+Uri.EscapeDataString(indicator.Value),"domain"=>"domains/"+Uri.EscapeDataString(indicator.Value),"hash"=>"files/"+indicator.Value,_=>"urls/"+Convert.ToBase64String(Encoding.UTF8.GetBytes(indicator.Value)).TrimEnd('=').Replace('+','-').Replace('/','_')};
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
            requests.Enqueue(now);daily++;IntelReport result;
            try
            {
                using var request=new HttpRequestMessage(HttpMethod.Get,"https://www.virustotal.com/api/v3/"+endpoint);
                request.Headers.TryAddWithoutValidation("x-apikey",config["VirusTotal:ApiKey"]);
                using var response=await clients.CreateClient("VirusTotal").SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
                if(response.StatusCode==HttpStatusCode.TooManyRequests){backoff=now.AddMinutes(1);result=Failure("RateLimited","VirusTotal quota reached. Retry later.");}
                else if(response.StatusCode==HttpStatusCode.NotFound)result=Failure("NotFound","No existing report. This does not mean the indicator is safe.") with {ExpiresAt=now.AddHours(1)};
                else if(!response.IsSuccessStatusCode)result=Failure("Unavailable","VirusTotal could not provide a report. Check API configuration or retry later.");
                else
                {
                    await response.Content.LoadIntoBufferAsync(2*1024*1024,timeout.Token);
                    using var doc=JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));
                    var a=doc.RootElement.GetProperty("data").GetProperty("attributes");var stats=a.GetProperty("last_analysis_stats");
                    var malicious=stats.GetProperty("malicious").GetInt32();var total=stats.EnumerateObject().Sum(x=>x.Value.GetInt32());
                    if(malicious<0 || total<malicious)throw new JsonException();
                    var categories=a.TryGetProperty("categories",out var cats)&&cats.ValueKind==JsonValueKind.Object?cats.EnumerateObject().Where(x=>x.Value.ValueKind==JsonValueKind.String).Select(x=>x.Value.GetString()!).Distinct().Take(20).Select(x=>x[..Math.Min(x.Length,200)]).ToArray():[];
                    result=new(indicator.Type,indicator.Value,"Available",malicious,total,categories,now,now.AddHours(24),"Existing reputation report; zero detections is not proof of safety.");
                }
            }
            catch(Exception ex) when(ex is HttpRequestException or OperationCanceledException or JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
            {if(ct.IsCancellationRequested)throw;result=Failure("Unavailable","Lookup failed or timed out. The original record is unaffected.");}
            cache.Set(key,result,new MemoryCacheEntryOptions{AbsoluteExpiration=result.ExpiresAt,Size=1});return result;
        }
        finally{gate.Release();}
    }
    public void Dispose(){cache.Dispose();gate.Dispose();}
}
