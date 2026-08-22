using System.ComponentModel.DataAnnotations;

namespace IncidentPlatform.Api.Configuration;

/// <summary>
/// Strongly-typed binding of the "Cors" section in appsettings.json.
///
/// Bound via AddOptions&lt;CorsSettings&gt;() with ValidateOnStart() in
/// Program.cs, which means a missing or empty AllowedOrigins list fails the
/// application at startup with a clear error — not the first time a browser
/// request hits a CORS-protected endpoint and mysteriously gets blocked.
/// </summary>
public sealed class CorsSettings
{
    /// <summary>
    /// Matches the "Cors" key in appsettings.json. Referenced from
    /// Program.cs so the string only appears in one place.
    /// </summary>
    public const string SectionName = "Cors";

    [Required]
    [MinLength(1, ErrorMessage = "At least one allowed origin must be configured.")]
    public string[] AllowedOrigins { get; init; } = [];
}