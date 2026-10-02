using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services.Ingestion;
using Xunit;

namespace IncidentPlatform.Tests;

/// <summary>Pure parser/normalizer tests — no web host or database.</summary>
public class LogParsingTests
{
    private static LogEvent Normalize(LogFormat format, string line) =>
        LogNormalizer.Normalize("test-src", format, line, LogParsers.Parse(format, line), new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));

    [Fact]
    public void Syslog_rfc5424_extracts_priority_timestamp_host_and_message()
    {
        var e = Normalize(LogFormat.Syslog, "<34>1 2026-10-02T03:04:05.000Z host01 sshd 1234 ID47 - Failed password for root");
        Assert.Equal(2, e.Severity);                 // 34 & 7 = 2 (critical)
        Assert.Equal("auth", e.Facility);            // 34 >> 3 = 4
        Assert.Equal(new DateTime(2026, 10, 2, 3, 4, 5, DateTimeKind.Utc), e.EventTime);
        Assert.Equal("host01", e.Host);
        Assert.Equal("Failed password for root", e.Message);
    }

    [Fact]
    public void Syslog_rfc5424_normalizes_offset_timestamp_to_utc()
    {
        var e = Normalize(LogFormat.Syslog, "<13>1 2026-10-02T06:04:05+03:00 h app - - - hello");
        Assert.Equal(new DateTime(2026, 10, 2, 3, 4, 5, DateTimeKind.Utc), e.EventTime);
    }

    [Fact]
    public void Syslog_rfc3164_parses_host_and_message_without_year()
    {
        var e = Normalize(LogFormat.Syslog, "<13>Oct  2 03:04:05 fw1 kernel: link down");
        Assert.Equal("fw1", e.Host);
        Assert.Equal(5, e.Severity);                 // 13 & 7 = 5 (notice)
        Assert.Equal("link down", e.Message);
        Assert.Equal(10, e.EventTime.Month);
        Assert.Equal(DateTimeKind.Utc, e.EventTime.Kind);
    }

    [Fact]
    public void Firewall_keyvalue_maps_src_dst_ports_protocol_and_action()
    {
        var e = Normalize(LogFormat.Firewall,
            "<38>Oct  2 03:04:05 fw1 fw: src=10.0.0.5 dst=8.8.8.8 spt=51000 dpt=53 proto=udp action=deny");
        Assert.Equal(LogSourceType.Firewall, e.SourceType);
        Assert.Equal("10.0.0.5", e.SourceIp);
        Assert.Equal("8.8.8.8", e.DestinationIp);
        Assert.Equal(51000, e.SourcePort);
        Assert.Equal(53, e.DestinationPort);
        Assert.Equal("udp", e.Protocol);
        Assert.Equal("deny", e.Action);
    }

    [Fact]
    public void Vpn_failed_login_is_recognized_and_raises_an_alert()
    {
        var e = Normalize(LogFormat.Vpn,
            "<38>Oct  2 03:04:05 vpn1 vpnd: user=jdoe action=login outcome=failure src=203.0.113.9");
        Assert.Equal(LogSourceType.Vpn, e.SourceType);
        Assert.Equal("jdoe", e.User);
        Assert.Equal("login", e.Action);
        Assert.Equal("failure", e.Outcome);
        Assert.Equal("203.0.113.9", e.SourceIp);

        var alert = IngestionRules.Evaluate(e);
        Assert.NotNull(alert);
        Assert.Equal("VPN-AUTH-FAILURE", alert!.SourceRuleId);
        Assert.Equal(AlertSource.Vpn, alert.Source);
    }

    [Fact]
    public void Json_maps_common_fields_and_normalizes_time_and_severity()
    {
        var e = Normalize(LogFormat.Json,
            "{\"timestamp\":\"2026-10-02T03:04:05Z\",\"src_ip\":\"1.2.3.4\",\"dst_ip\":\"5.6.7.8\",\"user\":\"bob\",\"action\":\"allow\",\"severity\":\"warning\",\"message\":\"ok\"}");
        Assert.Equal(new DateTime(2026, 10, 2, 3, 4, 5, DateTimeKind.Utc), e.EventTime);
        Assert.Equal("1.2.3.4", e.SourceIp);
        Assert.Equal("5.6.7.8", e.DestinationIp);
        Assert.Equal("bob", e.User);
        Assert.Equal(4, e.Severity);                 // "warning" -> 4
        Assert.Equal("ok", e.Message);
    }

    [Fact]
    public void Unparseable_line_keeps_raw_text_and_falls_back_to_received_time()
    {
        var received = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var line = "this is not a structured log line";
        var e = LogNormalizer.Normalize("s", LogFormat.Syslog, line, LogParsers.Parse(LogFormat.Syslog, line), received);
        Assert.Equal(line, e.RawLog);
        Assert.Equal(line, e.Message);
        Assert.Equal(received, e.EventTime);
        Assert.Equal(6, e.Severity);                 // default info
    }

    [Fact]
    public void Critical_severity_syslog_raises_an_alert()
    {
        var e = Normalize(LogFormat.Syslog, "<2>1 2026-10-02T03:04:05Z h app - - - disk failure");
        Assert.Equal(2, e.Severity);
        var alert = IngestionRules.Evaluate(e);
        Assert.NotNull(alert);
        Assert.Equal("LOG-CRITICAL-SEVERITY", alert!.SourceRuleId);
    }

    [Fact]
    public void Identical_line_from_same_source_has_a_stable_fingerprint()
    {
        var a = Normalize(LogFormat.Syslog, "<13>Oct  2 03:04:05 fw1 kernel: link down");
        var b = Normalize(LogFormat.Syslog, "<13>Oct  2 03:04:05 fw1 kernel: link down");
        Assert.Equal(a.Fingerprint, b.Fingerprint);
    }
}
