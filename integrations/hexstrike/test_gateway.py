import json, os, tempfile, unittest, uuid
from pathlib import Path
from unittest.mock import patch
from gateway import Gateway
class GatewayTests(unittest.TestCase):
 def test_disabled_default(self):
  with tempfile.TemporaryDirectory() as folder:
   g=Gateway(folder,[])
   self.assertEqual(g.capabilities()['profiles'],[])
   with self.assertRaises(ValueError):g.submit({'id':str(uuid.uuid4()),'target':'192.168.50.2','profile':'tcp-services'})
 def test_scope_and_idempotency(self):
  with tempfile.TemporaryDirectory() as folder:
   g=Gateway(folder,['192.168.50.2'],True);job={'id':str(uuid.uuid4()),'target':'192.168.50.2','profile':'tcp-services'}
   g.submit(job);g.submit(job)
   with g.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)
   for value in ['8.8.8.8','192.168.50.2;id']:
    with self.assertRaises(ValueError):g.submit({**job,'target':value})
 def test_fresh_evidence_and_failure_not_fabricated(self):
  with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'HEXSTRIKE_VERIFIED_VERSION':'6.0.0'}),patch('gateway.mcp_request',return_value=[]):
   g=Gateway(folder,['192.168.50.2'],True);job={'id':str(uuid.uuid4()),'target':'192.168.50.2','profile':'tcp-services'}
   def fixture(path,body=None,timeout=300):
    if path=='/health':return json.dumps({'status':'healthy','version':'6.0.0','tools_status':{'nmap':True}})
    self.assertEqual(path,'/api/tools/nmap');self.assertFalse(body['use_recovery'])
    Path(body['additional_args'].split(' -oX ')[1]).write_text('<nmaprun/>')
    return json.dumps({'success':True,'return_code':0,'timed_out':False,'stdout':'isolated test fixture'})
   g.upstream=fixture;g.submit(job);g.work();self.assertEqual(g.get(job['id'])['status'],'Completed');self.assertEqual(g.get(job['id'])['xml'],'<nmaprun/>')
   failed={**job,'id':str(uuid.uuid4())};g.submit(failed);g.upstream=lambda *a,**k: '{}';g.work();self.assertEqual(g.get(failed['id'])['status'],'Failed')
 def test_discovery_failure_is_stage_specific_and_recovers(self):
  with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'HEXSTRIKE_VERIFIED_VERSION':'6.0.0'}):
   g=Gateway(folder,['192.168.50.2'],True)
   g.upstream=lambda *a,**k:json.dumps({'status':'healthy','version':'6.0.0','tools_status':{'nmap':True}})
   with patch('gateway.mcp_request',side_effect=TimeoutError('private details')):
    failed=g.capabilities();self.assertFalse(failed['connected']);self.assertIn('MCP manifest',failed['message']);self.assertNotIn('private details',failed['message']);self.assertEqual(failed['tools'],[])
   with patch('gateway.mcp_request',return_value=[dict(name='nmap_scan',inputSchema={})]):
    ready=g.capabilities();self.assertTrue(ready['connected']);self.assertTrue(ready['tools'][0]['available'])
 def test_restart_does_not_repeat_running_scan(self):
  with tempfile.TemporaryDirectory() as folder:
   g=Gateway(folder,['192.168.50.2'],True);job={'id':str(uuid.uuid4()),'target':'192.168.50.2','profile':'tcp-services'};g.submit(job)
   with g.db() as db:db.execute("UPDATE jobs SET status='Running'")
   restored=Gateway(folder,['192.168.50.2'],True);self.assertEqual(restored.get(job['id'])['status'],'Failed')
if __name__=='__main__':unittest.main()
