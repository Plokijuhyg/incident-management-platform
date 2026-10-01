using System.Net;
using System.Security.Claims;
using System.Threading.RateLimiting;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace IncidentPlatform.Tests;

public class RateLimitingTests
{
    private static DefaultHttpContext Request(string controller, string action, string? user = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask,
            new EndpointMetadataCollection(new ControllerActionDescriptor { ControllerName = controller, ActionName = action }), "test"));
        if (user is not null)
            context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user)], "test"));
        return context;
    }

    [Theory]
    [InlineData("Evidence", "Upload", 20, 3600)]
    [InlineData("Incidents", "GetPaged", 300, 60)]
    [InlineData("Auth", "Login", 5, 900)]
    public void Policy_limits_are_enforced_without_queueing(string controller, string action, int permits, int seconds)
    {
        using var limiter = PartitionedRateLimiter.Create<HttpContext, string>(ApiRateLimiting.Partition);
        var request = Request(controller, action, "7");
        for (var n = 0; n < permits; n++)
        {
            using var lease = limiter.AttemptAcquire(request);
            Assert.True(lease.IsAcquired);
        }
        using var rejected = limiter.AttemptAcquire(request);
        Assert.False(rejected.IsAcquired);
        Assert.True(rejected.TryGetMetadata(MetadataName.RetryAfter, out var retry));
        Assert.InRange(retry.TotalSeconds, 1, seconds);
        var other = Request(controller, action, "8");
        other.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.2");
        using var isolated = limiter.AttemptAcquire(other);
        Assert.True(isolated.IsAcquired);
    }

    [Fact]
    public void Searches_share_a_user_budget_across_routes_but_not_with_other_users_or_regular_requests()
    {
        using var limiter = PartitionedRateLimiter.Create<HttpContext, string>(ApiRateLimiting.Partition);
        var search = Request("Iocs", "GetPaged", "7");
        search.Request.Method = "GET";
        search.Request.QueryString = new QueryString("?search=malware");
        for (var n = 0; n < 60; n++)
        {
            using var lease = limiter.AttemptAcquire(search);
            Assert.True(lease.IsAcquired);
        }
        var anotherRoute = Request("Assets", "GetPaged", "7");
        anotherRoute.Request.Method = "GET";
        anotherRoute.Request.QueryString = new QueryString("?search=other");
        using var rejected = limiter.AttemptAcquire(anotherRoute);
        Assert.False(rejected.IsAcquired);
        var anotherUser = Request("Assets", "GetPaged", "8");
        anotherUser.Request.Method = "GET";
        anotherUser.Request.QueryString = search.Request.QueryString;
        using var allowed = limiter.AttemptAcquire(anotherUser);
        Assert.True(allowed.IsAcquired);
        using var ordinary = limiter.AttemptAcquire(Request("Assets", "GetPaged", "7"));
        Assert.True(ordinary.IsAcquired);
    }

    [Fact]
    public void Login_budget_is_per_ip_and_email()
    {
        using var limiter = PartitionedRateLimiter.Create<HttpContext, string>(ApiRateLimiting.Partition);
        var one = Request("Auth", "Login");
        one.Items[LoginIdentityMiddleware.EmailKey] = "one@example.com";
        for (var n = 0; n < 5; n++) limiter.AttemptAcquire(one).Dispose();
        using var rejected = limiter.AttemptAcquire(one);
        Assert.False(rejected.IsAcquired);
        var two = Request("Auth", "Login");
        two.Items[LoginIdentityMiddleware.EmailKey] = "two@example.com";
        using var allowed = limiter.AttemptAcquire(two);
        Assert.True(allowed.IsAcquired);
    }
}
