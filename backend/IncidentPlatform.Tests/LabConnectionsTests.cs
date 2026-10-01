using System.Net;
using IncidentPlatform.Api.Services;
using Microsoft.Extensions.Configuration;

namespace IncidentPlatform.Tests;

public class LabConnectionsTests
{
    [Theory]
    [InlineData("http://8.8.8.8")]
    [InlineData("http://example.com")]
    [InlineData("http://127.0.0.1/tools")]
    [InlineData("http://user:password@127.0.0.1")]
    public async Task Rejects_destinations_without_sending_requests(string url)
    {
        var handler = new StubHandler("{}");
        var service = Create(url, handler);
        Assert.False((await service.Check("hexstrike", default)).Reachable);
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData("{\"status\":\"healthy\"}", true)]
    [InlineData("{\"status\":123}", false)]
    [InlineData("[]", false)]
    [InlineData("not json", false)]
    public async Task Validates_health_response(string response, bool expected)
    {
        var handler = new StubHandler(response);
        var result = await Create("http://127.0.0.1:8888", handler).Check("hexstrike", default);
        Assert.Equal(expected, result.Reachable);
        Assert.Equal("/health", handler.Path);
        Assert.Equal(1, handler.Calls);
    }

    private static LabConnections Create(string url, StubHandler handler) => new(
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Lab:HexStrikeUrl"] = url }).Build(),
        new Factory(handler));

    private sealed class Factory(StubHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, false);
    }
    private sealed class StubHandler(string content) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            Path = request.RequestUri?.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(content) });
        }
    }
}
