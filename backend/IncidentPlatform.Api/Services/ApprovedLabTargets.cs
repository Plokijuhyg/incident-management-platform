using System.Net;
namespace IncidentPlatform.Api.Services;
// One configuration source for scanning AND telemetry. Never trust a body-supplied IP.
public sealed class ApprovedLabTargets(IConfiguration config)
{
    public ApprovedAssessmentTarget[] All => config.GetSection("HexStrike:Targets").Get<ApprovedAssessmentTarget[]>() ?? [];
    public ApprovedAssessmentTarget? Find(string id) { var matches=All.Where(t => t.Approved && t.Id == id && AssessmentGateway.PrivateIp(t.Ip)).Take(2).ToArray(); return matches.Length==1 ? matches[0] : null; }
    public static bool SameAddress(string expected, IPAddress? actual) => actual is not null && IPAddress.TryParse(expected,out var ip) && ip.MapToIPv6().Equals(actual.MapToIPv6());
    public static string Machine(string value) => value.Trim().TrimEnd('.').ToUpperInvariant();
}
