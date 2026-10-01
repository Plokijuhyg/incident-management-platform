"""Single gateway policy for bounded presets. Names are joined to the live MCP manifest.
Unreviewed tools never become executable merely because MCP advertises them.
"""
import hashlib, json, re
from pathlib import Path
CATEGORIES = ("Network", "Web", "Cloud", "API")
GROUPS = {
 "Network": "nmap_scan nmap_advanced_scan masscan_high_speed rustscan_fast_scan amass_scan subfinder_scan nuclei_scan fierce_scan dnsenum_scan autorecon_scan autorecon_comprehensive arp_scan_discovery nbtscan_netbios rpcclient_enumeration enum4linux_scan enum4linux_ng_advanced smbmap_scan responder_credential_harvest netexec_scan",
 "Web": "gobuster_scan dirsearch_scan feroxbuster_scan ffuf_scan dirb_scan httpx_probe katana_crawl nikto_scan sqlmap_scan wpscan_analyze arjun_scan arjun_parameter_discovery paramspider_discovery paramspider_mining dalfox_xss_scan wafw00f_scan jaeles_vulnerability_scan x8_parameter_discovery burpsuite_scan zap_scan hakrawler_crawl wfuzz_scan xsser_scan",
 "Cloud": "prowler_scan scout_suite_assessment cloudmapper_analysis pacu_exploitation trivy_scan kube_hunter_scan kube_bench_cis docker_bench_security_scan clair_vulnerability_scan falco_runtime_monitoring checkov_iac_scan terrascan_iac_scan",
 "API": "api_fuzzer graphql_scanner jwt_analyzer api_schema_analyzer comprehensive_api_audit"
}
# Classification applies to these exact gateway presets, never arbitrary tool arguments.
PRESETS = {
 "nmap_scan": dict(category="Network",tier="safe",binary="nmap",description="TCP service inventory, ports 1-1024; bounded timeout; no NSE or recovery."),
 "nuclei_scan": dict(category="Web",tier="safe",binary="nuclei",description="Two reviewed HTTP GET templates; no redirects, callbacks, or template downloads."),
 "nikto_scan": dict(category="Web",tier="intrusive",binary="nikto",description="Bounded headers and paths checks on one explicit web endpoint; may trigger application logging.")
}

# Additional presets use only fixed arguments and the approved target/explicit URL path.
for name,binary,category,tier,description in [
 ('nmap_advanced_scan','nmap','Network','intrusive','Single SMB MS17-010 detection script on TCP 445; no exploitation or other NSE scripts.'),
 ('netexec_scan','nxc','Network','intrusive','SMB service enumeration of the single approved IP; no modules, credentials or remote commands.'),
 ('gobuster_scan','gobuster','Web','intrusive','Directory discovery with a small reviewed wordlist, one thread and delay; no redirects.'),
 ('dirb_scan','dirb','Web','intrusive','Non-recursive directory discovery with a small reviewed wordlist and delay.'),
 ('ffuf_scan','ffuf','Web','intrusive','Directory discovery, one thread, five requests/second and 90-second limit; no redirects.'),
 ('feroxbuster_scan','feroxbuster','Web','intrusive','Non-recursive content discovery, no link extraction, five requests/second and 90-second limit.'),
 ('dirsearch_scan','dirsearch','Web','intrusive','Non-recursive directory discovery with bounded rate and runtime; no redirects.'),
 ('wafw00f_scan','wafw00f','Web','intrusive','WAF fingerprinting of the explicit endpoint; redirects disabled.'),
 ('arjun_parameter_discovery','arjun','Web','intrusive','GET parameter discovery with a small wordlist, one thread and no redirects.'),
 ('arjun_scan','arjun','Web','intrusive','GET parameter discovery through the alternate MCP wrapper; fixed bounded options.'),
 ('enum4linux_scan','enum4linux','Network','intrusive','Anonymous SMB users, groups and shares enumeration; no RID brute force.'),
 ('enum4linux_ng_advanced','enum4linux-ng','Network','intrusive','Anonymous SMB users, groups and shares enumeration with corrected installed-wrapper options.'),
 ('smbmap_scan','smbmap','Network','intrusive','Anonymous SMB share enumeration; write-access probes disabled.'),
 ('rpcclient_enumeration','rpcclient','Network','intrusive','Anonymous RPC domain information; fixed read-only RPC commands.'),
 ('nbtscan_netbios','nbtscan','Network','safe','NetBIOS information from the single approved IP; no subnet sweep.'),
 ('api_fuzzer','curl','API','intrusive','GET-only checks of health, status and version under the explicit API path. Raw responses, no inferred vulnerabilities.'),
 ('graphql_scanner','curl','API','intrusive','Introspection, depth-two and ten-query batch checks on the explicit GraphQL path. Upstream hypotheses are unvalidated.'),
 ('api_schema_analyzer','curl','API','safe','Fetch and inspect the explicit OpenAPI/Swagger URL. Upstream hypotheses are unvalidated.')
]:PRESETS[name]=dict(category=category,tier=tier,binary=binary,description=description)

for name,preset in PRESETS.items():preset['endpoint']='api/tools/'+{'nmap_advanced_scan':'nmap-advanced','netexec_scan':'netexec','api_fuzzer':'api_fuzzer','graphql_scanner':'graphql_scanner','api_schema_analyzer':'api_schema_analyzer'}.get(name,preset['binary'])

# Scope requirements and known incompatibilities are visible, rather than hidden.
REASONS={
 'httpx_probe':'Installed httpx is the Python HTTP client, not ProjectDiscovery httpx required by this wrapper.',
 'masscan_high_speed':'Raw-socket privileges are not provisioned for the gateway; no automatic privilege escalation.',
 'rustscan_fast_scan':'Rustscan is not installed; its automatic Nmap behavior also needs a reviewed adapter.',
 'wpscan_analyze':'Needs a verified WordPress endpoint and reviewed redirect/update behavior.',
 'sqlmap_scan':'Needs an explicit parameterized request and an injection-testing preset; none is configured.',
 'jwt_analyzer':'Needs a target-specific test token supplied through a protected credential mechanism.',
 'comprehensive_api_audit':'Composite workflow invokes additional tools; use individual selected API checks.',
 'responder_credential_harvest':'Listens on a network segment and captures credentials; cannot be scoped to one approved target IP.',
}

def catalog(manifest, health):
 tools=[]
 for tool in manifest:
  name=tool['name']; preset=PRESETS.get(name)
  category=next((c for c,names in GROUPS.items() if name in names.split()),None)
  available=bool(preset and health.get('tools_status',{}).get(preset['binary']) is True)
  entry=dict(name=name,category=category,tier="unclassified",available=False,reason=REASONS.get(name,"Needs a reviewed execution adapter and the appropriate target scope."),description=tool.get('description','')[:1000],inputSchema=tool['inputSchema'])
  if preset: entry.update(category=preset['category'],tier=preset['tier'],description=preset['description'],available=available,reason="" if available else "Required executable is unavailable.")
  if category=='Cloud':entry['reason']='Cloud account/cluster authorization is not represented by a lab IP; execution unavailable.'
  tools.append(entry)
 root=Path(__file__).resolve().parent
 files=[root/name for name in ('scan_policy.py','selected_scans.py','mcp_transport.py','vulnerability_checks.py')]+sorted((root/'templates').glob('*.yaml'))
 implementation={file.name:hashlib.sha256(file.read_bytes()).hexdigest() for file in files}
 identity=hashlib.sha256(json.dumps(dict(version=2,tools=tools,implementation=implementation),sort_keys=True).encode()).hexdigest()
 return dict(tools=tools,manifestId=identity)

def resolve(value, capabilities):
 if not isinstance(value,dict) or not {'categories','selectedTools','manifestId','confirmed','webPort','webHttps'}.issubset(value):raise ValueError('Invalid selection fields')
 categories=value['categories']
 if not isinstance(categories,list) or not categories or any(c not in CATEGORIES for c in categories) or len(set(categories))!=len(categories):raise ValueError('Explicit categories required')
 if set(value)-{'categories','selectedTools','manifestId','confirmed','webPort','webHttps','webPath'}:raise ValueError('Invalid selection fields')
 if value['manifestId']!=capabilities['manifestId']:raise ValueError('Manifest or policy changed')
 if type(value['confirmed']) is not bool or type(value['webHttps']) is not bool or type(value['webPort']) is not int or not 1<=value['webPort']<=65535:raise ValueError('Invalid scope')
 path=value.get('webPath','/')
 if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9/_~.\-]{0,255}',path) or '//' in path or '..' in path.split('/'):raise ValueError('Use a plain target URL path without query, traversal or host override')
 names=value['selectedTools']; by_name={t['name']:t for t in capabilities['tools']}
 if names is None:names=[t['name'] for t in capabilities['tools'] if t['category'] in categories]
 if not isinstance(names,list) or not names or any(not isinstance(n,str) for n in names) or len(set(names))!=len(names):raise ValueError('Select tools')
 selected=[by_name.get(n) for n in names]
 if any(t is None or t['category'] not in categories or not t['available'] for t in selected):raise ValueError('Unavailable tool or category mismatch')
 if any(not any(t['category']==c for t in selected) for c in categories):raise ValueError('Every selected category needs a tool')
 if any(t['tier'] not in ('safe','intrusive','destructive') for t in selected):raise ValueError('Unclassified tool')
 if any(t['tier']!='safe' for t in selected) and value['confirmed'] is not True:raise ValueError('Explicit confirmation required')
 return dict(value,categories=sorted(categories),selectedTools=sorted(names),webPath=path)
