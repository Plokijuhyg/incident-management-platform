using System.Net;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services;

/// <summary>
/// Normalisation is mandatory before the UNIQIE (Type, Value) constraint
/// means anything (database-design.md §3.1) — otherwise EVIL.COM and
/// evil.com defeat deduplication entirely.
/// </summary>
public static class IocNormalizer
{
    public static string Normalize(IocType type, string rawValue)
    {
        var value = rawValue.Trim();

        // Strip common defanging: hxxp:// -> http://, [.] -> ., (.) -> .
        value = value
            .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase)
            .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
            .Replace("[.]", ".")
            .Replace("(.)", ".")
            .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase);

        return type switch
        {
            IocType.Domain or IocType.Email or IocType.Url => value.ToLowerInvariant(),
            IocType.HashMd5 or IocType.HashSha1 or IocType.HashSha256 => value.ToLowerInvariant(),
            IocType.IpAddress => NormalizeIp(value),
            _ => value
        };
    }

    private static string NormalizeIp(string value)
    {
        // Canonical form for IPv6 in particular (e.g. collapses ::0::0 vs
        // :: variants); falls back to the trimmed original if parsing fails
        // rather than throwing on a malformed value the caller will see
        // rejected downstream anyway.
        return IPAddress.TryParse(value, out var ip) ? ip.ToString() : value;
    }
}
