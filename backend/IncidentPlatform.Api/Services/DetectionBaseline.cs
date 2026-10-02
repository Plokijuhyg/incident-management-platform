using System.Text.Json;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Services;

/// <summary>
/// The curated detection baseline. Out of ~2,600 imported Sigma rules, most are
/// Sysmon-based and can never fire here (no Sysmon channel is collected), and many
/// are low severity. This picks the set worth enabling on the telemetry we actually
/// have: supported by the evaluator, mapped to a Windows <b>service</b> channel we
/// collect (not a Sysmon category), High or Critical, and not on the noise denylist.
/// The criteria are objective and explainable — this is tuning, not a magic list.
/// </summary>
public static class DetectionBaseline
{
    /// <summary>
    /// Sigma logsource <c>service</c> values whose channels we collect and the
    /// evaluator maps directly (see <see cref="SigmaConditions"/>). Category-based
    /// logsources (process_creation, network_connection, …) are deliberately excluded:
    /// they require the Sysmon channel, which is not collected, so they would add
    /// rules that can never match.
    /// </summary>
    public static readonly string[] SupportedServices =
        ["security", "system", "application", "windefend", "powershell", "powershell-classic"];

    /// <summary>
    /// Rules that are technically valid but too noisy / low-value to carry their own
    /// alert. "User Logoff Event" (Security 4634) fired 89 benign alerts in testing —
    /// textbook alert fatigue. Applying the baseline disables these and closes their
    /// open alerts.
    /// </summary>
    public static readonly string[] NoiseDenylist =
        ["0badd08f-c6a3-4630-90d3-6875cca440be"]; // User Logoff Event

    public static bool IsNoise(string externalRuleId) =>
        NoiseDenylist.Contains(externalRuleId, StringComparer.OrdinalIgnoreCase);

    /// <summary>The Sigma logsource service of a rule, or null if it is category-based or malformed.</summary>
    public static string? Service(DetectionRule rule)
    {
        try
        {
            using var doc = JsonDocument.Parse(rule.DefinitionJson);
            return doc.RootElement.TryGetProperty("logsource", out var ls) &&
                   ls.TryGetProperty("service", out var s) ? s.GetString() : null;
        }
        catch (JsonException) { return null; }
    }

    public static bool IsRecommended(DetectionRule rule)
    {
        if (IsNoise(rule.ExternalRuleId)) return false;
        if (rule.Severity is not ("High" or "Critical")) return false;
        var service = Service(rule);
        if (service is null || !SupportedServices.Contains(service)) return false;
        return SigmaConditions.Unsupported(rule) is null;
    }

    /// <summary>
    /// SQL that narrows the catalog to baseline candidates before the (C#-only) evaluator
    /// check runs on them — avoids loading every rule's JSON. Safe literal; no user input.
    /// </summary>
    public const string CandidateSql =
        "SELECT * FROM DetectionRules WHERE Severity IN ('High','Critical') " +
        "AND JSON_UNQUOTE(JSON_EXTRACT(DefinitionJson,'$.logsource.product'))='windows' " +
        "AND JSON_UNQUOTE(JSON_EXTRACT(DefinitionJson,'$.logsource.service')) " +
        "IN ('security','system','application','windefend','powershell','powershell-classic')";
}
