"""Private lab gateway. Execution is disabled unless explicitly configured on Kali."""
import hmac, ipaddress, json, os, sqlite3, ssl, threading, time, uuid
from pathlib import Path
from contextlib import contextmanager
import logging
from vulnerability_checks import run_checks
from scan_policy import catalog, resolve
from mcp_transport import request as mcp_request
from selected_scans import run_selected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): raise ValueError("Redirect rejected")

class Gateway:
 def __init__(self,root,targets,enabled=False):
  self.root=Path(root).resolve();self.targets=set(targets);self.enabled=enabled
  if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.:" for c in self.root.as_posix()):raise ValueError("Unsafe storage path")
  self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
  for target in targets:
   ip=ipaddress.ip_address(target)
   if not any(ip in ipaddress.ip_network(n) for n in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']):raise ValueError("Only approved private IPv4 targets")
  self.opener=build_opener(NoRedirect(),ProxyHandler({}))
  with self.db() as db:
   db.execute('CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,target TEXT,profile TEXT,status TEXT,result TEXT)')
   if 'selection' not in [r[1] for r in db.execute('PRAGMA table_info(jobs)')]:db.execute('ALTER TABLE jobs ADD COLUMN selection TEXT')
   db.execute("UPDATE jobs SET status='Failed',result=? WHERE status='Running'",(json.dumps({'error':'Gateway restarted; execution outcome unknown. Do not blindly rerun.'}),))
 @contextmanager
 def db(self):
  connection=sqlite3.connect(self.root/'jobs.sqlite3',timeout=10)
  try:
   with connection:yield connection
  finally:connection.close()
 def upstream(self,path,body=None,timeout=300):
  port=int(os.environ.get('HEXSTRIKE_PORT','8888'))
  request=Request(f'http://127.0.0.1:{port}'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
  with self.opener.open(request,timeout=timeout) as response:data=response.read(4*1024*1024+1)
  if len(data)>4*1024*1024:raise ValueError('Oversized response; not complete evidence')
  return data.decode('utf-8')
 def capabilities(self):
  if not self.enabled:return dict(connected=False,message='Execution disabled.',profiles=[],tools=[])
  stage='health'
  try:
   health=json.loads(self.upstream('/health',timeout=5))
   if health.get('version')!=os.environ.get('HEXSTRIKE_VERIFIED_VERSION') or health.get('status')!='healthy':raise ValueError('Unverified version')
   stage='MCP manifest'
   live=catalog(mcp_request(dict(operation='list'),timeout=20),health)
   return dict(live,connected=True,message='Live MCP manifest; availability is limited to reviewed target-scoped presets.',profiles=[])
  except Exception as error:
   logging.warning('Capability discovery failed at %s (%s)',stage,type(error).__name__)
   return dict(connected=False,message=f'{stage} unavailable; check the Kali gateway service. No tool execution is enabled.',profiles=[],tools=[])
 def selection(self,value):
  capabilities=self.capabilities()
  if not capabilities['connected']:raise ValueError('Live manifest unavailable')
  return resolve(value,capabilities)
 def submit(self,value):
  if not self.enabled:raise ValueError('Execution disabled')
  selected=value.get('profile')=='selected-tools'
  if set(value)!=({'id','target','profile','selection'} if selected else {'id','target','profile'}):raise ValueError('Unexpected parameters')
  job=str(uuid.UUID(value['id']))
  if value['target'] not in self.targets or value['profile'] not in ('tcp-services','vulnerability-checks','selected-tools'):raise ValueError('Unapproved scope')
  selection=json.dumps(value['selection'],sort_keys=True) if selected else None
  with self.db() as db:
   old=db.execute('SELECT target,profile,selection FROM jobs WHERE id=?',(job,)).fetchone()
   if old:
    if old!=(value['target'],value['profile'],selection):raise ValueError('Idempotency conflict')
    return {'id':job,'accepted':True}
  if value['profile']=='vulnerability-checks':raise ValueError('Use selected tools with explicit confirmation')
  if selected:
   if self.selection(value['selection'])!=value['selection']:raise ValueError('Selection must be resolved before submission')
  with self.db() as db:
   if db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('Pending','Running')").fetchone()[0]>=10:raise ValueError('Queue full')
   db.execute('INSERT OR IGNORE INTO jobs(id,target,profile,status,result,selection) VALUES(?,?,?,?,NULL,?)',(job,value['target'],value['profile'],'Pending',selection))
   old=db.execute('SELECT target,profile,selection FROM jobs WHERE id=?',(job,)).fetchone()
   if old!=(value['target'],value['profile'],selection):raise ValueError('Idempotency conflict')
  return {'id':job,'accepted':True}
 def get(self,job):
  job=str(uuid.UUID(job))
  with self.db() as db:r=db.execute('SELECT status,result FROM jobs WHERE id=?',(job,)).fetchone()
  if not r:raise KeyError(job)
  return {**(json.loads(r[1]) if r[1] else {}),'id':job,'status':r[0]}
 def work(self):
  if not self.enabled:return
  with self.db() as db:
   row=db.execute("SELECT id,target,profile,selection FROM jobs WHERE status='Pending' ORDER BY rowid LIMIT 1").fetchone()
   if not row:return
   db.execute("UPDATE jobs SET status='Running' WHERE id=?",(row[0],))
  result={'startedAt':time.time()};status='Failed'
  try:
   if row[1] not in self.targets or not self.capabilities()['connected']:raise ValueError('Scope or installed version no longer approved')
   folder=self.root/row[0];folder.mkdir(mode=0o700);output=folder/'nmap.xml'
   if row[2]=='selected-tools':
    selection=self.selection(json.loads(row[3]));checks,status=run_selected(folder,row[1],selection,mcp_request);result.update(checks)
    result['selection']=selection;result['finishedAt']=time.time()
    with self.db() as db:db.execute('UPDATE jobs SET status=?,result=? WHERE id=?',(status,json.dumps(result),row[0]))
    return
   if row[2]=='vulnerability-checks':
    checks,status=run_checks(self,folder,row[1]);result.update(checks)
    result['finishedAt']=time.time()
    with self.db() as db:db.execute('UPDATE jobs SET status=?,result=? WHERE id=?',(status,json.dumps(result),row[0]))
    return
   parameters={'target':row[1],'scan_type':'-sT -sV --version-light','ports':'1-1024','additional_args':f'-Pn --max-retries 1 --host-timeout 120s -oX {output.as_posix()}','use_recovery':False}
   result['parameters']=parameters
   raw=self.upstream('/api/tools/nmap',parameters);result['rawHexStrikeResponse']=raw
   (folder/'response.json').write_text(raw,encoding='utf-8');response=json.loads(raw)
   if output.exists() and output.stat().st_size<=4*1024*1024:result['xml']=output.read_text(encoding='utf-8')
   if response.get('success') is True and response.get('return_code')==0 and not response.get('timed_out') and result.get('xml'):status='Completed'
   else:result['error']='Tool failure, timeout or missing fresh XML. Original evidence retained.'
  except Exception as e:result['error']=f'Execution unconfirmed: {type(e).__name__}. Inspect Kali before retrying.'
  result['finishedAt']=time.time()
  with self.db() as db:db.execute('UPDATE jobs SET status=?,result=? WHERE id=?',(status,json.dumps(result),row[0]))

def main():
 token=os.environ['GATEWAY_TOKEN']
 if len(token)<32:raise ValueError('Random token must be at least 32 characters')
 gateway=Gateway(os.environ.get('GATEWAY_STORAGE','/var/lib/incident-platform-gateway'),json.loads(os.environ.get('APPROVED_TARGETS','[]')),os.environ.get('GATEWAY_ENABLE_EXECUTION')=='true')
 class Handler(BaseHTTPRequestHandler):
  def setup(self):
   super().setup();self.connection.settimeout(15)
  def log_message(self,*args):pass
  def run_request(self):
   if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token):self.send_error(401);return
   try:
    if self.command=='GET' and self.path=='/v1/capabilities':r=gateway.capabilities()
    elif self.command=='GET' and self.path.startswith('/v1/jobs/'):r=gateway.get(self.path.split('/')[-1])
    elif self.command=='POST' and self.path in ('/v1/jobs','/v1/selection'):
     length=int(self.headers.get('Content-Length','0'))
     if length<=0 or length>16384:raise ValueError('Invalid body length')
     value=json.loads(self.rfile.read(length));r=gateway.submit(value) if self.path=='/v1/jobs' else gateway.selection(value)
    else:self.send_error(404);return
    payload=json.dumps(r).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
   except KeyError:self.send_error(404)
   except (ValueError,TypeError):self.send_error(400)
   except Exception:self.send_error(503)
  do_GET=run_request
  do_POST=run_request
 def worker():
  while True:
   try:gateway.work()
   except Exception as e:logging.error("Gateway worker failure: %s",type(e).__name__)
   time.sleep(1)
 server=ThreadingHTTPServer((os.environ.get('GATEWAY_BIND','127.0.0.1'),int(os.environ.get('GATEWAY_PORT','9443'))),Handler)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
 context.load_cert_chain(os.environ['GATEWAY_CERT'],os.environ['GATEWAY_KEY'])
 context.load_verify_locations(os.environ['GATEWAY_CLIENT_CA']);context.verify_mode=ssl.CERT_REQUIRED
 server.socket=context.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=worker,daemon=True).start();server.serve_forever()
if __name__=='__main__':main()
