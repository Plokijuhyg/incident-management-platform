using System.Net;
using System.Text;
using IncidentPlatform.Api.Services;
using Microsoft.Extensions.Configuration;

namespace IncidentPlatform.Tests;

public class AssessmentGatewayTransportTests
{
    [Fact]
    public async Task Submission_has_known_content_length_for_python_gateway()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["HexStrike:Enabled"]="true", ["HexStrike:GatewayUrl"]="https://127.0.0.1:9443",
            ["HexStrike:GatewayToken"]=new string('x',32)
        }).Build();
        var handler = new LengthRequiredHandler();
        using var client = new HttpClient(handler);
        var gateway = new AssessmentGateway(config, new ClientFactory(client));
        var response = await gateway.Send(HttpMethod.Post,"/v1/jobs",new {id="job",target="192.168.207.129",profile="tcp-services"},CancellationToken.None);
        Assert.True(response.GetProperty("accepted").GetBoolean());
        Assert.True(handler.Seen);
    }
    [Fact]
    public void Result_preserves_scanner_severity_and_service_observations()
    {
        var xml="<nmaprun><host><ports><port portid='445' protocol='tcp'><state state='open'/><service name='microsoft-ds'/></port></ports></host><runstats><finished exit='success'/></runstats></nmaprun>";
        using var remote=System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(new {xml,findings=new[]{new {kind="Finding",severity="High",title="SMB vulnerability",evidence="scanner evidence"}}}));
        using var normalized=System.Text.Json.JsonDocument.Parse(AssessmentWorker.NormalizeResult(remote.RootElement));
        Assert.Equal(2,normalized.RootElement.GetArrayLength());
        Assert.Equal("Informational",normalized.RootElement[0].GetProperty("severity").GetString());
        Assert.Equal("High",normalized.RootElement[1].GetProperty("severity").GetString());
    }
    [Fact]
    public void Web_only_result_does_not_require_unselected_nmap_output()
    {
        using var remote=System.Text.Json.JsonDocument.Parse("{\"steps\":[{\"tool\":\"nuclei_scan\",\"status\":\"Completed\"}],\"findings\":[]}");
        Assert.Equal("[]",AssessmentWorker.NormalizeResult(remote.RootElement));
    }
    private sealed class ClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
    private sealed class LengthRequiredHandler : HttpMessageHandler
    {
        public bool Seen { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            // Read the header before serializing: the Python server rejects chunked JSON.
            var length=request.Content?.Headers.ContentLength;
            Assert.NotNull(length);
            var bytes=await request.Content!.ReadAsByteArrayAsync(ct);
            Assert.Equal((long)bytes.Length,length.Value);
            Seen=true;
            return new HttpResponseMessage(HttpStatusCode.OK) {Content=new StringContent("{\"accepted\":true}",Encoding.UTF8,"application/json")};
        }
    }
}
