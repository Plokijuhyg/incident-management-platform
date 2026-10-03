namespace IncidentPlatform.Api.Services;

/// <summary>
/// An offline, read-only mirror of the gateway's assessment policy
/// (<c>integrations/hexstrike/scan_policy.py</c>) so the platform can show which
/// security-assessment tools it supports <b>before</b> the Kali gateway is connected.
///
/// Two tiers of truth:
/// <list type="bullet">
/// <item><b>Reviewed</b> presets — a vetted, bounded run-adapter exists; these can execute
/// once the gateway is connected and the binary is installed.</item>
/// <item><b>Advertised</b> tools — named by the policy's category groups (and typically present
/// in the live MCP manifest) but with no reviewed adapter yet, so they are shown for planning
/// only and can never run until one is added.</item>
/// </list>
/// This is the honest catalog: it never claims a tool is runnable without a reviewed preset.
/// The live gateway may advertise more tools still (up to ~150); those appear only when connected.
/// Keep this in sync with scan_policy.py — <c>HexStrikeCatalogTests</c> guards the reviewed set.
/// </summary>
public static class HexStrikeCatalog
{
    public static readonly string[] Categories = ["Network", "Web", "Cloud", "API"];

    // scan_policy.py GROUPS — every tool name the policy recognizes, by category.
    private static readonly Dictionary<string, string[]> Groups = new()
    {
        ["Network"] = "nmap_scan nmap_advanced_scan masscan_high_speed rustscan_fast_scan amass_scan subfinder_scan nuclei_scan fierce_scan dnsenum_scan autorecon_scan autorecon_comprehensive arp_scan_discovery nbtscan_netbios rpcclient_enumeration enum4linux_scan enum4linux_ng_advanced smbmap_scan responder_credential_harvest netexec_scan".Split(' '),
        ["Web"] = "gobuster_scan dirsearch_scan feroxbuster_scan ffuf_scan dirb_scan httpx_probe katana_crawl nikto_scan sqlmap_scan wpscan_analyze arjun_scan arjun_parameter_discovery paramspider_discovery paramspider_mining dalfox_xss_scan wafw00f_scan jaeles_vulnerability_scan x8_parameter_discovery burpsuite_scan zap_scan hakrawler_crawl wfuzz_scan xsser_scan".Split(' '),
        ["Cloud"] = "prowler_scan scout_suite_assessment cloudmapper_analysis pacu_exploitation trivy_scan kube_hunter_scan kube_bench_cis docker_bench_security_scan clair_vulnerability_scan falco_runtime_monitoring checkov_iac_scan terrascan_iac_scan".Split(' '),
        ["API"] = "api_fuzzer graphql_scanner jwt_analyzer api_schema_analyzer comprehensive_api_audit".Split(' '),
    };

    // scan_policy.py PRESETS — the 21 reviewed run-adapters (category, tier, description).
    private static readonly Dictionary<string, (string Category, string Tier, string Description)> Presets = new()
    {
        ["nmap_scan"] = ("Network", "safe", "TCP service inventory, ports 1-1024; bounded timeout; no NSE or recovery."),
        ["nuclei_scan"] = ("Web", "safe", "Two reviewed HTTP GET templates; no redirects, callbacks, or template downloads."),
        ["nikto_scan"] = ("Web", "intrusive", "Bounded headers and paths checks on one explicit web endpoint; may trigger application logging."),
        ["nmap_advanced_scan"] = ("Network", "intrusive", "Single SMB MS17-010 detection script on TCP 445; no exploitation or other NSE scripts."),
        ["netexec_scan"] = ("Network", "intrusive", "SMB service enumeration of the single approved IP; no modules, credentials or remote commands."),
        ["gobuster_scan"] = ("Web", "intrusive", "Directory discovery with a small reviewed wordlist, one thread and delay; no redirects."),
        ["dirb_scan"] = ("Web", "intrusive", "Non-recursive directory discovery with a small reviewed wordlist and delay."),
        ["ffuf_scan"] = ("Web", "intrusive", "Directory discovery, one thread, five requests/second and 90-second limit; no redirects."),
        ["feroxbuster_scan"] = ("Web", "intrusive", "Non-recursive content discovery, no link extraction, five requests/second and 90-second limit."),
        ["dirsearch_scan"] = ("Web", "intrusive", "Non-recursive directory discovery with bounded rate and runtime; no redirects."),
        ["wafw00f_scan"] = ("Web", "intrusive", "WAF fingerprinting of the explicit endpoint; redirects disabled."),
        ["arjun_parameter_discovery"] = ("Web", "intrusive", "GET parameter discovery with a small wordlist, one thread and no redirects."),
        ["arjun_scan"] = ("Web", "intrusive", "GET parameter discovery through the alternate MCP wrapper; fixed bounded options."),
        ["enum4linux_scan"] = ("Network", "intrusive", "Anonymous SMB users, groups and shares enumeration; no RID brute force."),
        ["enum4linux_ng_advanced"] = ("Network", "intrusive", "Anonymous SMB users, groups and shares enumeration with corrected installed-wrapper options."),
        ["smbmap_scan"] = ("Network", "intrusive", "Anonymous SMB share enumeration; write-access probes disabled."),
        ["rpcclient_enumeration"] = ("Network", "intrusive", "Anonymous RPC domain information; fixed read-only RPC commands."),
        ["nbtscan_netbios"] = ("Network", "safe", "NetBIOS information from the single approved IP; no subnet sweep."),
        ["katana_crawl"] = ("Web", "intrusive", "Bounded crawl of one explicit web endpoint: depth 1, one worker, rate limited, no JS/headless, no update checks. Raw inventory only."),
        ["hakrawler_crawl"] = ("Web", "intrusive", "Bounded crawl of one explicit web endpoint: depth 1, one thread, no subdomains, TLS verified. Raw inventory only."),
        ["x8_parameter_discovery"] = ("Web", "intrusive", "Hidden GET parameter discovery on one explicit endpoint with a small reviewed wordlist and bounded concurrency; no payloads or exploitation."),
        ["api_fuzzer"] = ("API", "intrusive", "GET-only checks of health, status and version under the explicit API path. Raw responses, no inferred vulnerabilities."),
        ["graphql_scanner"] = ("API", "intrusive", "Introspection, depth-two and ten-query batch checks on the explicit GraphQL path. Upstream hypotheses are unvalidated."),
        ["api_schema_analyzer"] = ("API", "safe", "Fetch and inspect the explicit OpenAPI/Swagger URL. Upstream hypotheses are unvalidated."),
    };

    // scan_policy.py REASONS — why a named-but-unreviewed tool is unavailable.
    private static readonly Dictionary<string, string> Reasons = new()
    {
        ["httpx_probe"] = "Installed httpx is the Python HTTP client, not ProjectDiscovery httpx required by this wrapper.",
        ["masscan_high_speed"] = "Raw-socket privileges are not provisioned for the gateway; no automatic privilege escalation.",
        ["rustscan_fast_scan"] = "Rustscan is not installed; its automatic Nmap behavior also needs a reviewed adapter.",
        ["wpscan_analyze"] = "Needs a verified WordPress endpoint and reviewed redirect/update behavior.",
        ["sqlmap_scan"] = "Needs an explicit parameterized request and an injection-testing preset; none is configured.",
        ["jwt_analyzer"] = "Needs a target-specific test token supplied through a protected credential mechanism.",
        ["comprehensive_api_audit"] = "Composite workflow invokes additional tools; use individual selected API checks.",
        ["responder_credential_harvest"] = "Listens on a network segment and captures credentials; cannot be scoped to one approved target IP.",
    };

    // Tools that can never run in an IP-scoped lab regardless of gateway connection:
    // wrong package, missing privileges/binary, composite workflows, or cloud/credential scope.
    private static readonly HashSet<string> HardBlocked = new()
    {
        "httpx_probe", "masscan_high_speed", "rustscan_fast_scan", "responder_credential_harvest", "comprehensive_api_audit",
    };

    /// <param name="State">
    /// Authorization/readiness state the application assigns, independent of mere tool presence.
    /// Offline this is one of: <c>available</c> (a reviewed, bounded adapter exists — runnable once the
    /// gateway connects), <c>needs_setup</c> (advertised; requires a reviewed adapter and/or extra context
    /// before it can run), or <c>blocked</c> (cannot run in this lab model at all). A connected gateway
    /// refines these with live facts: <c>discovered</c>/<c>unavailable</c> (manifest presence and installed
    /// binary) and <c>authorized</c> (available AND permitted for the caller's approved target).
    /// </param>
    public sealed record ToolEntry(string Name, string Category, string Tier, string Status, string Description, string Reason, bool Runnable, string State);

    private static string OfflineState(string name, string category, bool reviewed) =>
        reviewed ? "available"
        : category == "Cloud" || HardBlocked.Contains(name) ? "blocked"
        : "needs_setup";

    public static IReadOnlyList<ToolEntry> Tools()
    {
        var entries = new List<ToolEntry>();
        foreach (var (groupCategory, names) in Groups)
        {
            foreach (var name in names)
            {
                if (Presets.TryGetValue(name, out var preset))
                {
                    entries.Add(new ToolEntry(name, preset.Category, preset.Tier, "reviewed", preset.Description, "", true, OfflineState(name, preset.Category, true)));
                }
                else
                {
                    var reason = groupCategory == "Cloud"
                        ? "Cloud account/cluster authorization is not represented by a lab IP; execution unavailable."
                        : Reasons.GetValueOrDefault(name, "Needs a reviewed execution adapter and the appropriate target scope.");
                    entries.Add(new ToolEntry(name, groupCategory, "unclassified", "advertised",
                        "Advertised by the tool manifest; no reviewed run-adapter yet.", reason, false, OfflineState(name, groupCategory, false)));
                }
            }
        }
        // Reviewed first, then by category, then name — stable and analyst-friendly.
        return entries
            .OrderByDescending(e => e.Runnable)
            .ThenBy(e => Array.IndexOf(Categories, e.Category))
            .ThenBy(e => e.Name, StringComparer.Ordinal)
            .ToList();
    }

    public static int ReviewedCount => Presets.Count;
}
