using System.Net;
using System.Text.Json;
using IncidentPlatform.Api.DTOs.Workspace;
using IncidentPlatform.Api.Exceptions;
namespace IncidentPlatform.Api.Services;
// Only configured local services are queried. No user-selected URL or tool execution endpoint.
public sealed class LabConnections(IConfiguration config, IHttpClientFactory clients)
{
    public LabConfiguration Configuration() => new(config["Lab:HexStrikeUrl"] ?? "http://127.0.0.1:8888", config["Lab:OllamaUrl"] ?? "http://127.0.0.1:11434");
    public async Task<ConnectionResult> Check(string service, CancellationToken ct)
    {
        var settings = Configuration();
        var url = service switch { "hexstrike" => settings.HexStrikeUrl, "ollama" => settings.OllamaUrl, _ => throw new ValidationAppException("Unknown service.") };
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !IPAddress.TryParse(uri.Host, out var ip) || !Local(ip))
            return new(service, url, false, "Configure a loopback or private lab IP URL without credentials or a path.", DateTime.UtcNow);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var client = clients.CreateClient("LabConnections");
            using var response = await client.GetAsync(new Uri(uri, service == "hexstrike" ? "/health" : "/api/tags"), HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            response.EnsureSuccessStatusCode();
            await response.Content.LoadIntoBufferAsync(262144, timeout.Token);
            using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));
            var ok = data.RootElement.ValueKind == JsonValueKind.Object && (service == "hexstrike" ? data.RootElement.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String && status.GetString() == "healthy" : data.RootElement.TryGetProperty("models", out var models) && models.ValueKind == JsonValueKind.Array);
            return new(service, url, ok, ok ? "Service responded successfully. This checks connectivity, not scan or model execution." : "Service replied with an unexpected format.", DateTime.UtcNow);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            if (ct.IsCancellationRequested) throw;
            return new(service, url, false, "Service unavailable or response invalid. Check the service and connection settings.", DateTime.UtcNow);
        }
    }
    private static bool Local(IPAddress ip) { if (IPAddress.IsLoopback(ip)) return true; var b = ip.GetAddressBytes(); return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 192 && b[1] == 168); }
}
