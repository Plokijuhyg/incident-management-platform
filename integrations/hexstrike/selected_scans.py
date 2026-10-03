"""Selected tools only: no implicit discovery, additional tools, or user command text."""
import hashlib, json
from pathlib import Path
from vulnerability_checks import nuclei_findings, nikto_findings, xml_root, smb_findings
from scan_policy import PRESETS

def extra_arguments(name,folder,target,url):
 # Wordlists are private per-job artifacts, not arbitrary paths from the request.
 paths=folder/'paths.txt';paths.write_text('admin\napi\nlogin\nrobots.txt\nsitemap.xml\nstatus\nhealth\nversion\nbackup\nconfig\nassets\nuploads\nserver-status\n.git/HEAD\n',encoding='utf-8')
 params=folder/'parameters.txt';params.write_text('id\npage\nsearch\nquery\nname\nlimit\noffset\nsort\nfilter\n',encoding='utf-8')
 wordlist=paths.as_posix()
 values={
 'netexec_scan':dict(target=target,protocol='smb',additional_args='--timeout 5'),
 'gobuster_scan':dict(url=url,mode='dir',wordlist=wordlist,additional_args='-t 1 --delay 200ms --timeout 5s --no-progress'),
 'dirb_scan':dict(url=url+'/' if not url.endswith('/') else url,wordlist=wordlist,additional_args='-r -z 200 -S'),
 'ffuf_scan':dict(url=url.rstrip('/'),wordlist=wordlist,mode='directory',match_codes='200,204,301,302,307,401,403',additional_args='-t 1 -rate 5 -timeout 5 -maxtime 90 -noninteractive'),
 'feroxbuster_scan':dict(url=url,wordlist=wordlist,threads=1,additional_args='--no-recursion --dont-extract-links --rate-limit 5 --time-limit 90s --timeout 5 --silent'),
 'dirsearch_scan':dict(url=url,wordlist=wordlist,threads=1,recursive=False,extensions='html,txt,json',additional_args='--max-rate 5 --max-time 90 --timeout 5'),
 'wafw00f_scan':dict(target=url,additional_args='--noredirect --timeout 5'),
 'katana_crawl':dict(url=url,additional_args='-depth 1 -concurrency 1 -rate-limit 5 -timeout 5 -no-color -silent -disable-update-check -headless=false -js-crawl=false'),
 'hakrawler_crawl':dict(url=url,additional_args='-d 1 -t 1 -timeout 5 -subs=false -insecure=false'),
 'x8_parameter_discovery':dict(url=url,wordlist=params.as_posix(),additional_args='-c 1 --max 8'),
 'arjun_parameter_discovery':dict(url=url,method='GET',wordlist=params.as_posix(),delay=1,threads=1,stable=True,additional_args='--disable-redirects -T 5'),
 'arjun_scan':dict(url=url,method='GET',additional_args='-w '+params.as_posix()+' -t 1 -d 1 --stable --disable-redirects -T 5'),
 'enum4linux_scan':dict(target=target,additional_args='-U -G -S'),
 # Installed endpoint incorrectly generates -A S,U,G,P; use individual flags instead.
 'enum4linux_ng_advanced':dict(target=target,shares=False,users=False,groups=False,policy=False,additional_args='-U -G -S -t 5'),
 'smbmap_scan':dict(target=target,additional_args='--no-write-check --no-color --timeout 5'),
 'rpcclient_enumeration':dict(target=target,commands='querydominfo',additional_args="-N -c querydominfo"),
 'nbtscan_netbios':dict(target=target,verbose=True,timeout=2000,additional_args=''),
 'api_fuzzer':dict(base_url=url,endpoints='health,status,version',methods='GET'),
 'graphql_scanner':dict(endpoint=url,introspection=True,query_depth=2,test_mutations=False),
 'api_schema_analyzer':dict(schema_url=url,schema_type='openapi')
 }
 if name not in values:raise ValueError('Missing scoped adapter')
 return values[name]

def response_success(name,response):
 if not isinstance(response,dict) or response.get('success') is not True or response.get('timed_out'):return False
 if name=='api_fuzzer':
  results=response.get('results',[])
  return len(results)==3 and all(r.get('result',{}).get('success') is True and r['result'].get('return_code')==0 for r in results)
 if name in ('graphql_scanner','api_schema_analyzer'):
  # These upstream analyzers omit transport evidence. Never normalize their guesses as findings.
  return True
 return response.get('return_code')==0

def run_selected(folder,target,selection,invoke):
 result=dict(steps=[],findings=[],coverage="Only explicitly selected bounded presets; one explicit endpoint for Web/API. No implicit discovery or exploitation.")
 for name in selection['selectedTools']:
  url=('https' if selection['webHttps'] else 'http')+'://'+target+':'+str(selection['webPort'])+selection.get('webPath','/')
  if name=='nmap_scan':
   out=folder/'nmap.xml';endpoint=target
   arguments=dict(target=target,scan_type='-sT -sV --version-light',ports='1-1024',additional_args=f'-Pn --max-retries 1 --host-timeout 120s -oX {out.as_posix()}')
  elif name=='nmap_advanced_scan':
   out=folder/'smb.xml';endpoint=target
   arguments=dict(target=target,scan_type='-sT',ports='445',timing='T2',nse_scripts='smb-vuln-ms17-010',os_detection=False,version_detection=False,aggressive=False,stealth=False,additional_args=f'-Pn --script-timeout 45s --host-timeout 90s -oX {out.as_posix()}')
  elif name=='nuclei_scan':
   out=folder/'nuclei.jsonl';endpoint=url
   arguments=dict(target=url,template=(Path(__file__).resolve().parent/'templates').as_posix(),additional_args=f'-jsonl -o {out.as_posix()} -no-stdin -disable-redirects -no-interactsh -disable-update-check -rate-limit 5 -concurrency 1 -timeout 5 -retries 0')
  elif name=='nikto_scan':
   out=folder/'nikto.json';endpoint=url
   arguments=dict(target=url,additional_args=f'-Tuning 123b -Plugins "headers;paths;report_json" -nocheck -maxtime 90s -timeout 5 -Pause 0.2 -nointeractive -ask no -nolookup -Format json -output {out.with_suffix("").as_posix()}')
  else:
   out=None;endpoint=target if PRESETS[name]['category']=='Network' else url
   arguments=extra_arguments(name,folder,target,url)
  step=dict(tool=name,endpoint=endpoint,status='Failed',parameters=arguments,providerMayCache=out is None);result['steps'].append(step)
  try:
   response=invoke(dict(operation='call',name=name,arguments=arguments))
   raw=json.dumps(response);(folder/(name+'.response.json')).write_text(raw,encoding='utf-8')
   step['responseSha256']=hashlib.sha256(raw.encode()).hexdigest()
   if not response_success(name,response):raise ValueError('Tool did not complete successfully')
   if out is None:
    step.update(evidence=raw[:131072],evidenceTruncated=len(raw)>131072,status='Completed',sha256=step['responseSha256'],interpretation='Raw provider output; claims require analyst validation. Not normalized as vulnerability findings. HexStrike may reuse cached results for identical requests.')
    if name in ('graphql_scanner','api_schema_analyzer'):
     step['status']='Unverified';step['interpretation']='Upstream heuristic output lacks complete transport evidence; execution and vulnerability claims are unverified.'
    continue
   if not out.exists() or out.stat().st_size>1024*1024:raise ValueError('Missing or oversized fresh evidence')
   text=out.read_text(encoding='utf-8');step.update(evidence=text[:131072],evidenceTruncated=len(text)>131072,sha256=hashlib.sha256(text.encode()).hexdigest())
   if name=='nmap_scan':xml_root(text);result['xml']=text
   elif name=='nmap_advanced_scan':result['findings'].extend(smb_findings(text,target))
   else:result['findings'].extend(nuclei_findings(text,url) if name=='nuclei_scan' else nikto_findings(text,url))
   step['status']='Completed'
  except Exception as error:step['error']=str(error)[:250] if isinstance(error,ValueError) else type(error).__name__
 successes=sum(s['status']=='Completed' for s in result['steps'])
 return result,('Completed' if successes==len(result['steps']) else 'Partial' if successes or any(s['status']=='Unverified' for s in result['steps']) else 'Failed')
