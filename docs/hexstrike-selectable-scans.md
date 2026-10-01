# Selectable HexStrike assessments

## Investigation and resulting design

Before this change, SecurityAssessment stored Profile, RawResponse, ObservationsJson and EvidenceSha256. Vulnerability-check responses already contained per-tool steps. There is no separate Findings table. AssessmentService offered two fixed workflows and AssessmentGateway called a private HTTPS gateway that used HexStrike HTTP routes, not MCP.

The installed Kali MCP manifest was queried using initialize and tools/list: 150 tool definitions, with no category or Blast-Radius annotations. There was no implemented Blast-Radius policy to reuse. The gateway now has one policy, scan_policy.py, describing categories and exact bounded execution presets. It is not a claim that upstream supplied these classifications. Names and input schemas come from the installed MCP server, not a UI tool list. Tools without reviewed adapters remain unavailable. Unmapped live tools remain in the manifest with no category and cannot execute.

The approved migration adds nullable RequestJson to the existing SecurityAssessments table. The private gateway adds a selection column to its existing SQLite jobs table. Existing findings, alerts, incidents and audit tables remain unchanged. Requested scope is retained alongside per-tool evidence in the existing assessment record.

## Request and execution

POST /api/assessments/scan (Admin or SecurityManager):

```json
{
  "targetId": "metasploitable3",
  "categories": ["Network", "Web"],
  "selectedTools": ["nmap_scan", "nuclei_scan"],
  "manifestId": "value-from-GET-capabilities",
  "confirmed": false,
  "webPort": 80,
  "webHttps": false,
  "webPath": "/"
}
```

Categories are Network, Web, Cloud, API. At least one is required. selectedTools is a flat list of MCP tool names; each must belong to a selected category, and every selected category must have a selected tool. If omitted/null, every advertised tool in the explicit categories is considered: an unavailable or unclassified tool rejects the whole request, rather than silently skipping it. An explicit empty list is invalid.

GET /api/assessments/capabilities returns tools, inputSchema, category, scoped tier, available, reason, and manifestId. Changing manifest or availability invalidates a stale selection. The UI resets confirmation when selection changes. The server rechecks confirmation and availability at admission and execution. Unknown tools fail closed. The previous POST creation route no longer admits fixed workflows; existing historical records remain readable.

Target approval uses the existing ApprovedLabTargets resolver over HexStrike:Targets. There is no second target registry. The existing private gateway also enforces its provisioned IP boundary. Rejections use the telemetry pattern: error and traceId response plus AuditLogs ASSESSMENT_REJECTED / Denied. No ordinary alert or incident is created by denial or by selecting tools.

Gateway requests use the existing HTTPS/mTLS transport. Inside Kali, mcp_transport.py runs the installed HexStrike tool definitions via MCP stdio, using tools/list and tools/call. A narrow client adapter sends their HTTP requests only to the local HexStrike service and forces use_recovery=false (the installed nmap wrapper otherwise enables it). Redirects and proxies are disabled. There is no public arbitrary-command or arbitrary-tools/call endpoint.

Job IDs are idempotent across the target, profile and full resolved selection. A policy, adapter, template or manifest change before execution fails the job. Lost acknowledgements reconcile the same job, and gateway restart marks previously running jobs as unknown/failed instead of rerunning them.

## Available presets and limitations

The current Metasploitable3 scope supports 21 MCP tool definitions, provided their dependencies are available:

| Category | Presets |
| --- | --- |
| Network | nmap_scan, nmap_advanced_scan, netexec_scan, enum4linux_scan, enum4linux_ng_advanced, smbmap_scan, rpcclient_enumeration, nbtscan_netbios |
| Web | nuclei_scan, nikto_scan, gobuster_scan, dirb_scan, ffuf_scan, feroxbuster_scan, dirsearch_scan, wafw00f_scan, arjun_parameter_discovery, arjun_scan |
| API | api_fuzzer, graphql_scanner, api_schema_analyzer |

These are 21 named MCP presets, including two Arjun wrappers, not 21 distinct installed binaries. The category selector has an explicit Select available tools action. It does not enable unsupported tools or automatically confirm intrusive checks.

Nmap inventory and NetBIOS discovery are safe-tier. Advanced Nmap is intrusive-tier and executes only the reviewed smb-vuln-ms17-010 script on TCP 445, with no exploitation. SMBMap disables write-access testing; anonymous RPC/SMB presets do not accept arbitrary commands or credentials. Enum4linux-ng uses individual options to avoid the installed upstream wrapper's invalid -A S,U,G,P combination.

Nuclei retains two reviewed GET templates. Web directory/parameter discovery uses short per-job wordlists and constrained rate/concurrency where supported. Redirects are disabled or not enabled; recursion/link extraction is disabled in discovery presets. Nikto, directory/parameter discovery and WAF fingerprinting require intrusive confirmation. Arjun's two wrappers use the same bounded GET policy.

API fuzzer performs three GET requests (health/status/version) under the explicit path, and checks nested tool failures. GraphQL uses introspection, depth two and the installed scanner's ten-query batch; it requires confirmation. The installed GraphQL and schema analyzers omit complete transport evidence and can emit unreliable heuristics: their results are retained as **Unverified**, making the assessment Partial, and are never normalized into vulnerability findings. Schema analysis is safe-tier but remains heuristic.

The target-relative webPath defaults to /. A user can specify /graphql or /openapi.json as appropriate. No query, hostname override, traversal, shell text, or arbitrary tool arguments are accepted. Mixing tools against one endpoint does not prove that endpoint supports every protocol. Only selected tools run; selecting Web or API never implicitly invokes Nmap.

Available means the dependency and reviewed adapter are present, not that a scan has succeeded on the target. Cloud remains unavailable because the user selected Metasploitable3 only. Domain reconnaissance needs domain scope. Masscan requires raw-socket permissions not provisioned here. The installed httpx is the Python HTTP client, not the ProjectDiscovery binary expected by the wrapper. Other tools show their missing scope/adapter requirements instead of pretending every advertised MCP tool applies to this VM. No destructive preset, credential attack, arbitrary command or exploitation feature is enabled.

The three original parsers plus the explicit SMB NSE check normalize findings. Other tools retain their original output with per-step status, parameters, preview and SHA-256 for review, without invented severity. HexStrike caches successful identical command strings; raw-output presets disclose that execution freshness is not guaranteed. Full original responses remain in the private per-job Kali directory. Provider heuristics, cached output, failed checks and empty findings are not proof of security or exploitability.

The manifest identity covers live tool metadata/availability plus policy, adapter code and reviewed template hashes. A change invalidates queued stale selections rather than silently changing their execution.

## Operation

Apply the AddAssessmentSelection migration before starting the updated API:

```powershell
dotnet ef database update --project backend/IncidentPlatform.Api
```

Deploy gateway.py, vulnerability_checks.py, scan_policy.py, selected_scans.py, mcp_transport.py and the reviewed templates together into the existing private Kali gateway directory, with no queued/running jobs. Restart the existing gateway service. The provisioning script includes these files for initial setup; it also changes connection settings, so ordinary code-only updates should preserve existing secrets and approval configuration.

HexStrike must be running on Kali loopback port 8888, and the existing SSH 9443 tunnel must be active. Use Check gateway in Security Assessments, choose the approved target, select categories/tools, and confirm intrusive checks. A disconnected health/manifest state blocks new execution.

## Verification

Python tests cover scope, confirmation, omitted selection, stale manifest, idempotency, target revocation and Web-only dispatch. The installed Kali MCP contract test uses a temporary loopback HTTP fixture: it verifies real tools/list and tools/call for all 21 presets and checks recovery is disabled without scanning a target. API tests use the isolated test database; Angular tests exercise the manifest-driven selection and confirmation request. No fixture evidence is inserted into the real application database.
