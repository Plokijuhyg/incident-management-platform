"""Installed-MCP contract test: loopback HTTP fixtures only, never real scans."""
import json, os, threading, unittest, tempfile, shlex
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from mcp_transport import request
from scan_policy import PRESETS
from selected_scans import run_selected

@unittest.skipUnless(Path('/usr/share/hexstrike-ai/hexstrike_mcp.py').exists(),'Installed Kali MCP required')
class McpContractTests(unittest.TestCase):
 def test_manifest_and_exact_calls_disable_wrapper_recovery(self):
  manifest=request(dict(operation='list'),timeout=20)
  self.assertTrue({'nmap_scan','nuclei_scan','nikto_scan'}.issubset({t['name'] for t in manifest}))
  seen=[]
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));seen.append((self.path,body))
    value=json.dumps(dict(success=True,return_code=0,stdout='isolated fixture',results=[dict(result=dict(success=True,return_code=0)) for _ in range(3)])).encode()
    args=shlex.split(body.get('additional_args',''))
    if self.path in ('/api/tools/nmap','/api/tools/nmap-advanced'):
     Path(args[args.index('-oX')+1]).write_text('<nmaprun><host/><runstats><finished exit="success"/></runstats></nmaprun>')
    elif self.path=='/api/tools/nuclei':Path(args[args.index('-o')+1]).write_text('')
    elif self.path=='/api/tools/nikto':Path(args[args.index('-output')+1]+'.json').write_text('[]')

    self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(value)));self.end_headers();self.wfile.write(value)
  server=HTTPServer(('127.0.0.1',0),Handler)
  threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   with patch.dict(os.environ,{'HEXSTRIKE_PORT':str(server.server_port)}),tempfile.TemporaryDirectory() as folder:
    selection=dict(selectedTools=list(PRESETS),webHttps=False,webPort=80,webPath='/')
    result,status=run_selected(Path(folder),'192.168.207.129',selection,request)
    self.assertEqual([s['tool'] for s in result['steps']],list(PRESETS))
    self.assertEqual([s for s in result['steps'] if s['status']=='Failed'],[])
    self.assertEqual(status,'Partial') # Two heuristic analyzers lack transport evidence.
   self.assertEqual([p for p,_ in seen],['/'+p['endpoint'] for p in PRESETS.values()])
   self.assertTrue(all(body['use_recovery'] is False for _,body in seen))
  finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
