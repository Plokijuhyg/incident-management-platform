using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IncidentPlatform.Tests;

// The generic execution path: the application discovers tools from the connected gateway,
// enforces identity/target/tool authorization, and delegates execution to HexStrike. It never
// builds a command or runs a binary itself.
public class ToolExecutionTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;
    public ToolExecutionTests(TestApiFactory factory) => _factory = factory;

    private sealed class GatewayHandler : HttpMessageHandler
    {
        public int CapabilityCalls;
        public int SelectionCalls;
        public bool Connected = true;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/v1/capabilities")
            {
                CapabilityCalls++;
                var payload = new
                {
                    connected = Connected,
                    manifestId = "fixture",
                    message = "fixture",
                    profiles = Array.Empty<object>(),
                    tools = Connected
                        ? new object[]
                        {
                            new { name = "katana_crawl", category = "Web", tier = "intrusive", available = true, reason = "" },
                            new { name = "nmap_scan", category = "Network", tier = "safe", available = true, reason = "" },
                            new { name = "sqlmap_scan", category = "Web", tier = "unclassified", available = false, reason = "Needs an explicit parameterized request." },
                        }
                        : Array.Empty<object>(),
                };
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(payload) };
            }
            if (path == "/v1/selection")
            {
                SelectionCalls++;
                var value = await request.Content!.ReadFromJsonAsync<JsonElement>(ct);
                return value.GetProperty("manifestId").GetString() == "fixture"
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(value) }
                    : new HttpResponseMessage(HttpStatusCode.BadRequest);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    [Fact]
    public async Task Generic_execution_discovers_authorizes_and_delegates_to_hexstrike()
    {
        var handler = new GatewayHandler();
        using var app = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HexStrike:Enabled"] = "true", ["HexStrike:GatewayUrl"] = "https://127.0.0.1:9443", ["HexStrike:GatewayToken"] = new string('x', 32),
                ["HexStrike:Targets:0:Id"] = "exec-fixture", ["HexStrike:Targets:0:Name"] = "Exec fixture", ["HexStrike:Targets:0:Ip"] = "192.168.207.129", ["HexStrike:Targets:0:Approved"] = "true",
            }));
            b.ConfigureServices(s => s.AddHttpClient("AssessmentGateway").ConfigurePrimaryHttpMessageHandler(() => handler));
        });

        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var email = $"exec-{Guid.NewGuid():N}@example.com";
        var actor = new User { Email = email, FullName = "Exec test", PasswordHash = scope.ServiceProvider.GetRequiredService<IPasswordHasher>().Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
        db.Users.Add(actor); await db.SaveChangesAsync();
        var role = await db.Roles.SingleAsync(r => r.Name == RoleNames.Admin);
        db.UserRoles.Add(new() { UserId = actor.Id, RoleId = role.Id, AssignedById = actor.Id, AssignedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();

        using var client = app.CreateClient();
        try
        {
            var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
            login.EnsureSuccessStatusCode();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken);

            object Body(string tool, string target = "exec-fixture", string? ip = null) =>
                new { toolName = tool, targetId = target, targetIp = ip, confirmed = true, webPort = 8080, webHttps = false, webPath = "/" };

            // Discovered + available tool → delegated to the gateway selection/job path.
            var ok = await client.PostAsJsonAsync("/api/assessments/execute", Body("katana_crawl"));
            Assert.Equal(HttpStatusCode.Accepted, ok.StatusCode);
            var row = await ok.Content.ReadFromJsonAsync<SecurityAssessment>();
            var stored = await db.SecurityAssessments.AsNoTracking().SingleAsync(r => r.Id == row!.Id);
            Assert.Equal("selected-tools", stored.Profile);
            Assert.Equal("Pending", stored.Status);
            using (var sel = JsonDocument.Parse(stored.RequestJson!))
            {
                Assert.Equal("katana_crawl", sel.RootElement.GetProperty("selectedTools")[0].GetString());
                Assert.Equal("Web", sel.RootElement.GetProperty("categories")[0].GetString());
            }

            var afterSelection = handler.SelectionCalls;

            // Unknown tool (not discovered) → 400, no execution.
            Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/assessments/execute", Body("totally_unknown_tool"))).StatusCode);
            // Discovered but not authorized (needs setup) → 409, no execution.
            Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync("/api/assessments/execute", Body("sqlmap_scan"))).StatusCode);
            // Unapproved public target override → 403, rejected before any gateway call.
            var beforeCaps = handler.CapabilityCalls;
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/assessments/execute", Body("katana_crawl", target: "", ip: "8.8.8.8"))).StatusCode);
            Assert.Equal(beforeCaps, handler.CapabilityCalls);
            // None of the rejected calls submitted a selection.
            Assert.Equal(afterSelection, handler.SelectionCalls);
        }
        finally
        {
            using var s = app.Services.CreateScope();
            var d = s.ServiceProvider.GetRequiredService<AppDbContext>();
            await d.SecurityAssessments.Where(a => a.RequestedById == actor.Id).ExecuteDeleteAsync();
            await d.RefreshTokens.Where(t => t.UserId == actor.Id).ExecuteDeleteAsync();
            await d.UserRoles.Where(r => r.UserId == actor.Id).ExecuteDeleteAsync();
            await d.AuditLogs.Where(a => a.ActorUserId == actor.Id || a.ActorEmail == email || a.EntityId == "8.8.8.8").ExecuteDeleteAsync();
            await d.Users.Where(u => u.Id == actor.Id).ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Generic_execution_reports_an_unavailable_gateway_without_executing()
    {
        var handler = new GatewayHandler { Connected = false };
        using var app = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureAppConfiguration((_, c) => c.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HexStrike:Enabled"] = "true", ["HexStrike:GatewayUrl"] = "https://127.0.0.1:9443", ["HexStrike:GatewayToken"] = new string('x', 32),
                ["HexStrike:Targets:0:Id"] = "exec-fixture2", ["HexStrike:Targets:0:Name"] = "Exec fixture", ["HexStrike:Targets:0:Ip"] = "192.168.207.129", ["HexStrike:Targets:0:Approved"] = "true",
            }));
            b.ConfigureServices(s => s.AddHttpClient("AssessmentGateway").ConfigurePrimaryHttpMessageHandler(() => handler));
        });

        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var email = $"exec-{Guid.NewGuid():N}@example.com";
        var actor = new User { Email = email, FullName = "Exec test", PasswordHash = scope.ServiceProvider.GetRequiredService<IPasswordHasher>().Hash("Password123!"), IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
        db.Users.Add(actor); await db.SaveChangesAsync();
        var role = await db.Roles.SingleAsync(r => r.Name == RoleNames.Admin);
        db.UserRoles.Add(new() { UserId = actor.Id, RoleId = role.Id, AssignedById = actor.Id, AssignedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();

        using var client = app.CreateClient();
        try
        {
            var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest { Email = email, Password = "Password123!" });
            login.EnsureSuccessStatusCode();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<LoginResponse>())!.AccessToken);

            var response = await client.PostAsJsonAsync("/api/assessments/execute", new { toolName = "katana_crawl", targetId = "exec-fixture2", confirmed = true, webPort = 8080, webHttps = false, webPath = "/" });
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(0, handler.SelectionCalls);
            Assert.Equal(0, await db.SecurityAssessments.CountAsync(a => a.RequestedById == actor.Id));
        }
        finally
        {
            using var s = app.Services.CreateScope();
            var d = s.ServiceProvider.GetRequiredService<AppDbContext>();
            await d.SecurityAssessments.Where(a => a.RequestedById == actor.Id).ExecuteDeleteAsync();
            await d.RefreshTokens.Where(t => t.UserId == actor.Id).ExecuteDeleteAsync();
            await d.UserRoles.Where(r => r.UserId == actor.Id).ExecuteDeleteAsync();
            await d.AuditLogs.Where(a => a.ActorUserId == actor.Id || a.ActorEmail == email).ExecuteDeleteAsync();
            await d.Users.Where(u => u.Id == actor.Id).ExecuteDeleteAsync();
        }
    }
}
