using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services.Ingestion;

/// <summary>Intermediate result of the Parse stage, before normalization to a <see cref="LogEvent"/>.</summary>
public sealed class ParsedFields
{
    /// <summary>Event time as stated by the log, already converted to UTC. Null if the log carried none.</summary>
    public DateTime? Timestamp { get; set; }
    public string? Host { get; set; }
    /// <summary>Syslog severity 0..7, if the line carried a PRI or a usable level field.</summary>
    public int? Severity { get; set; }
    public string? Facility { get; set; }
    public string Message { get; set; } = "";
    /// <summary>Every other key/value the parser recovered, keyed case-insensitively.</summary>
    public Dictionary<string, string> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Stage 2 (Parse). Pure, allocation-light, regex-timeout-guarded parsers for the
/// framings a non-Windows SOC feed actually arrives in. Nothing here touches the
/// database or throws on bad input: an unparseable line still yields its raw text
/// as the message, so ingestion never loses evidence.
/// </summary>
public static class LogParsers
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);
    private static readonly string[] Facilities =
    [
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
        "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
        "local3", "local4", "local5", "local6", "local7"
    ];

    private static readonly Regex Rfc3164 = new(
        @"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$",
        RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex Tag = new(
        @"^([^:\s\[]{1,48})(?:\[\d+\])?:?\s*(.*)$",
        RegexOptions.CultureInvariant | RegexOptions.Singleline, RegexTimeout);
    private static readonly Regex KeyValue = new(
        "([A-Za-z_][\\w.\\-]{0,63})=(\"[^\"]*\"|'[^']*'|[^\\s]+)",
        RegexOptions.CultureInvariant, RegexTimeout);

    public static ParsedFields Parse(LogFormat format, string line)
    {
        var parsed = format switch
        {
            LogFormat.Json => ParseJson(line),
            LogFormat.KeyValue => ParseKeyValueLine(line),
            _ => ParseSyslog(line), // Syslog, Firewall, Vpn share the syslog framing
        };
        return parsed;
    }

    private static ParsedFields ParseSyslog(string line)
    {
        var fields = new ParsedFields { Message = line };
        var rest = line;
        if (line.StartsWith('<'))
        {
            var close = line.IndexOf('>');
            if (close > 1 && int.TryParse(line.AsSpan(1, close - 1), out var pri) && pri is >= 0 and <= 191)
            {
                fields.Severity = pri & 7;
                fields.Facility = Facilities[(pri >> 3) % Facilities.Length];
                rest = line[(close + 1)..];
                // RFC 5424 begins with a single version digit then a space.
                if (rest.Length > 1 && char.IsDigit(rest[0]) && rest[1] == ' ')
                {
                    ParseRfc5424(rest[2..].TrimStart(), fields);
                    FoldMessageKeyValues(fields);
                    return fields;
                }
            }
        }
        if (!ParseRfc3164(rest, fields)) fields.Message = rest;
        FoldMessageKeyValues(fields);
        return fields;
    }

    private static void ParseRfc5424(string s, ParsedFields f)
    {
        // TIMESTAMP HOST APP PROCID MSGID [STRUCTURED-DATA] MSG
        var p = s.Split(' ', 6);
        if (p.Length < 6) { f.Message = s; return; }
        if (p[0] != "-" && DateTimeOffset.TryParse(p[0], CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts))
            f.Timestamp = ts.UtcDateTime;
        if (p[1] != "-") f.Host = p[1];
        if (p[2] != "-") f.Fields["app"] = p[2];
        var tail = p[5];
        if (tail.StartsWith("- ")) tail = tail[2..];
        else if (tail == "-") tail = "";
        else if (tail.StartsWith('['))
        {
            // Pull key="value" pairs out of each [id k="v" ...] element, then the message follows.
            var cut = 0;
            while (cut < tail.Length && tail[cut] == '[')
            {
                var end = tail.IndexOf(']', cut);
                if (end < 0) break;
                foreach (Match m in KeyValue.Matches(tail[cut..end]))
                    f.Fields.TryAdd(m.Groups[1].Value, Unquote(m.Groups[2].Value));
                cut = end + 1;
            }
            tail = tail[cut..].TrimStart();
        }
        f.Message = tail;
    }

    private static bool ParseRfc3164(string s, ParsedFields f)
    {
        var m = Rfc3164.Match(s);
        if (!m.Success) return false;
        if (DateTime.TryParseExact(Regex.Replace(m.Groups[1].Value, @"\s+", " "),
                ["MMM d HH:mm:ss", "MMM dd HH:mm:ss"], CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts))
        {
            // RFC 3164 omits the year; assume the current UTC year, rolling back one near Jan 1.
            var now = DateTime.UtcNow;
            ts = new DateTime(now.Year, ts.Month, ts.Day, ts.Hour, ts.Minute, ts.Second, DateTimeKind.Utc);
            if (ts > now.AddDays(1)) ts = ts.AddYears(-1);
            f.Timestamp = ts;
        }
        f.Host = m.Groups[2].Value;
        var tagMatch = Tag.Match(m.Groups[3].Value);
        if (tagMatch.Success)
        {
            f.Fields["app"] = tagMatch.Groups[1].Value;
            f.Message = tagMatch.Groups[2].Value;
        }
        else f.Message = m.Groups[3].Value;
        return true;
    }

    private static ParsedFields ParseKeyValueLine(string line)
    {
        var f = new ParsedFields { Message = line };
        foreach (Match m in KeyValue.Matches(line))
            f.Fields[m.Groups[1].Value] = Unquote(m.Groups[2].Value);
        return f;
    }

    // Firewall/VPN syslog messages are usually "key=value key=value"; lift those out too.
    private static void FoldMessageKeyValues(ParsedFields f)
    {
        if (!f.Message.Contains('=')) return;
        foreach (Match m in KeyValue.Matches(f.Message))
            f.Fields.TryAdd(m.Groups[1].Value, Unquote(m.Groups[2].Value));
    }

    private static ParsedFields ParseJson(string line)
    {
        var f = new ParsedFields { Message = line };
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return f;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var value = prop.Value.ValueKind switch
                {
                    JsonValueKind.String => prop.Value.GetString(),
                    JsonValueKind.Number => prop.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Null or JsonValueKind.Undefined => null,
                    _ => prop.Value.GetRawText(),
                };
                if (value is not null) f.Fields[prop.Name] = value;
            }
            if (f.Fields.TryGetValue("message", out var msg) || f.Fields.TryGetValue("msg", out msg)) f.Message = msg;
        }
        catch (JsonException) { /* not JSON after all — keep the raw line as the message */ }
        return f;
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && (value[0] == '"' || value[0] == '\'') && value[^1] == value[0]
            ? value[1..^1] : value;

    public static string Fingerprint(string source, string rawLine) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source + "\n" + rawLine)));
}
