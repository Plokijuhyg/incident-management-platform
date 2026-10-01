using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using IncidentPlatform.Api.Exceptions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace IncidentPlatform.Tests;

public class ExceptionHandlerTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public ExceptionHandlerTests(TestApiFactory factory)
    {
        _factory = factory;
    }

    private HttpClient CreateClientWithTestEndpoint(string path, Action throwAction)
    {
        return _factory.WithWebHostBuilder(builder =>
        {
            builder.Configure((IApplicationBuilder app) =>
            {
                app.UseExceptionHandler();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet(path, () => throwAction());
                });
            });
        }).CreateClient();
    }

    [Fact]
    public async Task UnexpectedException_Returns500WithGenericMessage()
    {
        var client = CreateClientWithTestEndpoint("/__test/unexpected", () =>
            throw new InvalidOperationException("Boom"));

        var response = await client.GetAsync("/__test/unexpected");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.NotNull(body);
        Assert.Equal(500, ((JsonElement)body!["status"]).GetInt32());
    }

    [Fact]
    public async Task NotFoundException_Returns404WithItsOwnMessage()
    {
        var client = CreateClientWithTestEndpoint("/__test/notfound", () =>
            throw new NotFoundException("Customer", 42));

        var response = await client.GetAsync("/__test/notfound");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.NotNull(body);
        Assert.Equal(404, ((JsonElement)body!["status"]).GetInt32());
        Assert.Equal("Customer with id '42' was not found.", body["title"].ToString());
    }

    [Fact]
    public async Task ConflictException_Returns409()
    {
        var client = CreateClientWithTestEndpoint("/__test/conflict", () =>
            throw new ConflictException("Email already in use."));

        var response = await client.GetAsync("/__test/conflict");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task ForbiddenException_Returns403()
    {
        var client = CreateClientWithTestEndpoint("/__test/forbidden", () =>
            throw new ForbiddenException("Not allowed to modify this incident."));

        var response = await client.GetAsync("/__test/forbidden");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
