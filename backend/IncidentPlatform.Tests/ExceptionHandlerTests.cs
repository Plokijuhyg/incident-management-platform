using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace IncidentPlatform.Tests;

public class ExceptionHandlerTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ExceptionHandlerTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task UnhandledException_ReturnsProblemDetailsWith500()
    {
        // We don't have a real business endpoint that throws yet, so we
        // replace only the *pipeline* (not the services) with one that maps
        // a single endpoint guaranteed to throw. This still exercises the
        // real GlobalExceptionHandler, since it was registered in
        // Program.cs's service configuration, which this doesn't touch.
        var client = _factory.WithWebHostBuilder(builder =>
        {
            builder.Configure(app =>
            {
                app.UseExceptionHandler();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/__test/throw", () =>
                    {
                        throw new InvalidOperationException("Boom");
                    });
                });
            });
        }).CreateClient();

        var response = await client.GetAsync("/__test/throw");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.NotNull(body);
        Assert.True(body!.ContainsKey("status"));
        Assert.True(body.ContainsKey("title"));
    }
}