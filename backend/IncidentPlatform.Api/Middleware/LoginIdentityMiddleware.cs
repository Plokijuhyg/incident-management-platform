using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace IncidentPlatform.Api.Middleware;

public sealed class LoginIdentityMiddleware(RequestDelegate next)
{
    public const string EmailKey = "LoginEmail";

    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>();
        if (endpoint is { ControllerName: "Auth", ActionName: "Login" })
        {
            // Read only a bounded login body, then rewind it for MVC. Never inspect uploads.
            const int maxBytes = 16 * 1024;
            context.Request.EnableBuffering();
            var buffer = new byte[maxBytes + 1];
            var length = 0;
            while (length < buffer.Length)
            {
                var read = await context.Request.Body.ReadAsync(buffer.AsMemory(length), context.RequestAborted);
                if (read == 0) break;
                length += read;
            }
            context.Request.Body.Position = 0;
            if (length > maxBytes)
            {
                await Results.Problem(statusCode: 413, title: "Login request is too large.").ExecuteAsync(context);
                return;
            }
            try
            {
                using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
                if (json.RootElement.ValueKind == JsonValueKind.Object)
                    foreach (var property in json.RootElement.EnumerateObject())
                        if (property.Name.Equals("email", StringComparison.OrdinalIgnoreCase) &&
                            property.Value.ValueKind == JsonValueKind.String)
                            context.Items[EmailKey] = property.Value.GetString()!.Trim().ToLowerInvariant();
            }
            catch (JsonException) { /* MVC returns its standard validation error. */ }
        }
        await next(context);
    }
}
