import json, tempfile, unittest, uuid
from pathlib import Path
from unittest.mock import patch
from gateway import Gateway
from scan_policy import catalog, resolve, PRESETS
from selected_scans import run_selected, extra_arguments, response_success

class SelectionTests(unittest.TestCase):
 def setUp(self):
  self.cap=catalog([dict(name=n,inputSchema={}) for n in ('nmap_scan','nuclei_scan','nikto_scan','prowler_scan','execute_command')],dict(tools_status=dict(nmap=True,nuclei=True,nikto=True)))
  self.value=dict(categories=['Web'],selectedTools=['nuclei_scan'],manifestId=self.cap['manifestId'],confirmed=False,webPort=8080,webHttps=False)
 def test_manifest_is_source_of_tool_presence(self):
  self.assertEqual(catalog([],dict(tools_status=dict(nmap=True)))['tools'],[])
  self.assertFalse(next(t for t in self.cap['tools'] if t['name']=='execute_command')['available'])
 def test_confirmation_and_category_validation(self):
  self.assertEqual(resolve(self.value,self.cap)['selectedTools'],['nuclei_scan'])
  for changes in (dict(categories=[]),dict(categories=['Cloud'],selectedTools=['prowler_scan']),dict(selectedTools=['execute_command']),dict(selectedTools=['nmap_scan']),dict(selectedTools=[]),dict(selectedTools=['nikto_scan']),dict(manifestId='old'),dict(webPort=0),dict(confirmed='true')):
   with self.subTest(changes=changes),self.assertRaises(ValueError):resolve(dict(self.value,**changes),self.cap)
  self.assertEqual(resolve(dict(self.value,selectedTools=['nikto_scan'],confirmed=True),self.cap)['selectedTools'],['nikto_scan'])
 def test_omitted_tools_expands_explicit_categories_and_requires_confirmation(self):
  with self.assertRaises(ValueError):resolve(dict(self.value,selectedTools=None),self.cap)
  self.assertEqual(resolve(dict(self.value,selectedTools=None,confirmed=True),self.cap)['selectedTools'],['nikto_scan','nuclei_scan'])
 def test_availability_change_invalidates_selection(self):
  cap=catalog([dict(name='nuclei_scan',inputSchema={})],dict(tools_status=dict(nuclei=False)))
  with self.assertRaises(ValueError):resolve(self.value,cap)
 def test_web_only_calls_only_selected_tool(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp);calls=[]
   def invoke(value):
    calls.append(value);(folder/'nuclei.jsonl').write_text('')
    return dict(success=True,return_code=0)
   result,status=run_selected(folder,'192.168.207.129',self.value,invoke)
   self.assertEqual(status,'Completed');self.assertNotIn('xml',result)
   self.assertEqual([c['name'] for c in calls],['nuclei_scan'])
   self.assertEqual(calls[0]['arguments']['target'],'http://192.168.207.129:8080/')
 def test_failure_does_not_invent_results(self):
  with tempfile.TemporaryDirectory() as temp:
   result,status=run_selected(Path(temp),'192.168.207.129',self.value,lambda v:dict(success=False,return_code=1))
   self.assertEqual(status,'Failed');self.assertEqual(result['findings'],[])
 def test_gateway_selection_idempotency_and_revocation(self):
  with tempfile.TemporaryDirectory() as temp:
   gateway=Gateway(temp,['192.168.207.129'],True)
   gateway.capabilities=lambda:dict(self.cap,connected=True)
   job=dict(id=str(uuid.uuid4()),target='192.168.207.129',profile='selected-tools',selection=resolve(self.value,self.cap))
   gateway.submit(job);gateway.submit(job)
   with self.assertRaises(ValueError):gateway.submit(dict(job,selection=dict(job['selection'],webPort=80)))
   gateway.targets.clear()
   with self.assertRaises(ValueError):gateway.submit(job)
   with patch('gateway.mcp_request') as invoke:
    gateway.work();invoke.assert_not_called()
   self.assertEqual(gateway.get(job['id'])['status'],'Failed')
 def test_policy_change_before_execution_fails_without_invocation(self):
  with tempfile.TemporaryDirectory() as temp:
   gateway=Gateway(temp,['192.168.207.129'],True);gateway.capabilities=lambda:dict(self.cap,connected=True)
   job=dict(id=str(uuid.uuid4()),target='192.168.207.129',profile='selected-tools',selection=resolve(self.value,self.cap));gateway.submit(job)
   self.cap['manifestId']='changed'
   with patch('gateway.mcp_request') as invoke:gateway.work();invoke.assert_not_called()
   self.assertEqual(gateway.get(job['id'])['status'],'Failed')

 def test_target_path_cannot_override_host_or_inject_command(self):
  for path in ['//evil.example','/../admin','/x;id','/x?command=id','/x#y',"/a'b"]:
   with self.subTest(path=path),self.assertRaises(ValueError):resolve(dict(self.value,webPath=path),self.cap)
 def test_expanded_adapters_preserve_scope_and_disable_dangerous_defaults(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp);target='192.168.207.129';url='http://'+target+':8080/api'
   for name in PRESETS:
    if name in ('nmap_scan','nmap_advanced_scan','nuclei_scan','nikto_scan'):continue
    args=extra_arguments(name,folder,target,url)
    self.assertTrue(any(v in (target,url,url+'/') for v in args.values()),name)
   ng=extra_arguments('enum4linux_ng_advanced',folder,target,url)
   self.assertFalse(ng['shares']);self.assertIn('-S',ng['additional_args'])
   smb=extra_arguments('smbmap_scan',folder,target,url);self.assertIn('--no-write-check',smb['additional_args'])
   api=extra_arguments('api_fuzzer',folder,target,url);self.assertEqual(api['methods'],'GET')
 def test_api_nested_failure_is_not_reported_as_success(self):
  self.assertFalse(response_success('api_fuzzer',dict(success=True,results=[dict(result=dict(success=False,return_code=1))]*3)))
 def test_poc_tool_runs_through_the_same_generic_path(self):
  # A newly-added preset (katana_crawl) executes through run_selected's generic MCP
  # call loop with no tool-specific execution code — only a bounded argument adapter.
  self.assertIn('katana_crawl',PRESETS)
  cap=catalog([dict(name=n,inputSchema={}) for n in ('katana_crawl',)],dict(tools_status=dict(katana=True)))
  value=dict(categories=['Web'],selectedTools=['katana_crawl'],manifestId=cap['manifestId'],confirmed=True,webPort=8080,webHttps=False,webPath='/')
  self.assertEqual(resolve(value,cap)['selectedTools'],['katana_crawl'])
  with tempfile.TemporaryDirectory() as temp:
   calls=[]
   def invoke(v):calls.append(v);return dict(success=True,return_code=0)
   result,status=run_selected(Path(temp),'192.168.207.129',value,invoke)
   self.assertEqual(status,'Completed')
   self.assertEqual([c['name'] for c in calls],['katana_crawl'])
   self.assertEqual(calls[0]['operation'],'call')
   self.assertEqual(calls[0]['arguments']['url'],'http://192.168.207.129:8080/')
   self.assertIn('-depth 1',calls[0]['arguments']['additional_args'])
