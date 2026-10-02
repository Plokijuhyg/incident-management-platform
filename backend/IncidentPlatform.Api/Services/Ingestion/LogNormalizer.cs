using System.Globalization;
using System.Text.Json;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services.Ingestion;

/// <summary>
/// Stage 3 (Normalize). Maps vendor-specific field names onto the common
/// <see cref="LogEvent"/> schema and puts every event on one UTC timeline, so
/// firewall, VPN and syslog feeds become comparable and jointly queryable.
/// </summary>
public static class LogNormalizer
{
    // Alias → canonical column. First alias present wins. Lower-cased lookups.
    private static readonly string[] SourceIpKeys = ["src", "srcip", "src_ip", "source", "sourceip", "source.ip", "saddr", "sourceaddress", "client", "clientip"];
    private static readonly string[] DestIpKeys = ["dst", "dstip", "dst_ip", "dest", "destination", "destinationip", "destination.ip", "daddr", "destinationaddress", "target"];
    private static readonly string[] SourcePortKeys = ["spt", "srcport", "sport", "src_port", "source.port"];
    private static readonly string[] DestPortKeys = ["dpt", "dstport", "dport", "dst_port", "destination.port"];
    private static readonly string[] ProtocolKeys = ["proto", "protocol", "ipproto"];
    private static readonly string[] ActionKeys = ["act", "action", "disposition", "event", "msg_type"];
    private static readonly string[] OutcomeKeys = ["outcome", "result", "status", "event.outcome"];
    private static readonly string[] UserKeys = ["user", "usr", "username", "user.name", "account", "suser", "uid", "login"];
    private static readonly string[] HostKeys = ["host", "hostname", "dvc", "device", "devname", "host.name", "observer"];
    private static readonly string[] TimeKeys = ["timestamp", "time", "@timestamp", "eventtime", "event_time", "date", "ts"];
    private static readonly string[] SeverityKeys = ["severity", "level", "loglevel", "pri", "syslog.severity"];

    public static LogEvent Normalize(string source, LogFormat format, string rawLine, ParsedFields parsed, DateTime receivedAt)
    {
        var e = new LogEvent
        {
            Source = source,
            SourceType = format switch
            {
                LogFormat.Firewall => LogSourceType.Firewall,
                LogFormat.Vpn => LogSourceType.Vpn,
                LogFormat.Syslog => LogSourceType.Syslog,
                LogFormat.Json or LogFormat.KeyValue => LogSourceType.Generic,
                _ => LogSourceType.Generic,
            },
            RawLog = rawLine,
            Message = Trim(parsed.Message, 8000) ?? rawLine,
            ReceivedAt = receivedAt,
            Facility = Trim(parsed.Facility, 32),
            Host = Trim(parsed.Host ?? First(parsed, HostKeys), 255),
            Fingerprint = LogParsers.Fingerprint(source, rawLine),
        };

        e.EventTime = parsed.Timestamp ?? ParseTime(First(parsed, TimeKeys)) ?? receivedAt;
        e.Severity = parsed.Severity ?? ParseSeverity(First(parsed, SeverityKeys)) ?? 6;

        e.SourceIp = Ip(First(parsed, SourceIpKeys));
        e.DestinationIp = Ip(First(parsed, DestIpKeys));
        e.SourcePort = Port(First(parsed, SourcePortKeys));
        e.DestinationPort = Port(First(parsed, DestPortKeys));
        e.Protocol = Trim(First(parsed, ProtocolKeys), 16);
        e.Action = Trim(First(parsed, ActionKeys), 64)?.ToLowerInvariant();
        e.Outcome = NormalizeOutcome(First(parsed, OutcomeKeys));
        e.User = Trim(First(parsed, UserKeys), 255);

        // Keep the remaining parsed pairs as evidence, minus the ones promoted to columns.
        var consumed = new HashSet<string>(
            SourceIpKeys.Concat(DestIpKeys).Concat(SourcePortKeys).Concat(DestPortKeys)
                .Concat(ProtocolKeys).Concat(ActionKeys).Concat(OutcomeKeys).Concat(UserKeys)
                .Concat(HostKeys).Concat(TimeKeys).Concat(SeverityKeys),
            StringComparer.OrdinalIgnoreCase);
        var extra = parsed.Fields.Where(kv => !consumed.Contains(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value);
        if (extra.Count > 0) e.FieldsJson = JsonSerializer.Serialize(extra);

        return e;
    }

    private static string? First(ParsedFields p, string[] keys)
    {
        foreach (var key in keys)
            if (p.Fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        return null;
    }

    private static DateTime? ParseTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
            return dto.UtcDateTime;
        // Epoch seconds or milliseconds.
        if (long.TryParse(value, out var epoch))
        {
            try
            {
                return (epoch > 100_000_000_000
                    ? DateTimeOffset.FromUnixTimeMilliseconds(epoch)
                    : DateTimeOffset.FromUnixTimeSeconds(epoch)).UtcDateTime;
            }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        return null;
    }

    private static int? ParseSeverity(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (int.TryParse(value, out var n) && n is >= 0 and <= 7) return n;
        return value.Trim().ToLowerInvariant() switch
        {
            "emerg" or "emergency" or "fatal" => 0,
            "alert" => 1,
            "crit" or "critical" => 2,
            "err" or "error" => 3,
            "warn" or "warning" => 4,
            "notice" => 5,
            "info" or "informational" or "information" => 6,
            "debug" or "trace" or "verbose" => 7,
            _ => null,
        };
    }

    private static string? NormalizeOutcome(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim().ToLowerInvariant();
        if (v is "success" or "succeeded" or "allow" or "allowed" or "accept" or "accepted" or "ok" or "pass" or "0") return "success";
        if (v is "fail" or "failed" or "failure" or "deny" or "denied" or "drop" or "dropped" or "block" or "blocked" or "error" or "reject") return "failure";
        return Trim(v, 32);
    }

    private static string? Ip(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        return System.Net.IPAddress.TryParse(v, out var ip) ? ip.ToString() : Trim(v, 45);
    }

    private static int? Port(string? value) =>
        int.TryParse(value, out var p) && p is >= 0 and <= 65535 ? p : null;

    private static string? Trim(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Length > max ? value[..max] : value;
}
