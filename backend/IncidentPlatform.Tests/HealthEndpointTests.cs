using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace IncidentPlatform.Tests;

/// <summary>
/// Verifies the application actually boots and serves a request end to end.
/// This is the first integration test and establishes the pattern the
/// authorization tests in docs/security.md §11 will use: host the real
/// application in memory, then assert on genuine HTTP responses.
/// </summary>
public class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public HealthEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task Health_endpoint_returns_ok_when_the_application_is_running()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Unknown_route_returns_not_found()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/does-not-exist");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
