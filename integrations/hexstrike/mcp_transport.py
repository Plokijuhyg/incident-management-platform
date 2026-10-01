"""Real MCP stdio transport to the installed HexStrike tool definitions.
The adapter prevents HexStrike's nmap wrapper from enabling automatic recovery.
No public general-purpose tool-call endpoint is exposed by the gateway.
"""
import asyncio, json, os, subprocess, sys
from pathlib import Path

def request(value, timeout=320):
 completed=subprocess.run([sys.executable,str(Path(__file__).resolve())],input=json.dumps(value),text=True,capture_output=True,timeout=timeout)
 if completed.returncode:raise ValueError("MCP transport failed")
 if len(completed.stdout)>4*1024*1024:raise ValueError("Oversized MCP response")
 return json.loads(completed.stdout)

def serve():
 sys.path.insert(0,'/usr/share/hexstrike-ai')
 from hexstrike_mcp import setup_mcp_server
 from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
 class NoRedirect(HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise ValueError('Redirect rejected')
 class ScopedClient:
  def safe_post(self,endpoint,json_data):
   from scan_policy import PRESETS
   endpoints={p['endpoint'] for p in PRESETS.values()}
   if endpoint not in endpoints:raise ValueError('Tool endpoint not permitted')
   payload=dict(json_data,use_recovery=False)
   req=Request('http://127.0.0.1:'+str(int(os.environ.get('HEXSTRIKE_PORT','8888')))+'/'+endpoint,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
   with build_opener(NoRedirect(),ProxyHandler({})).open(req,timeout=300) as response:raw=response.read(4*1024*1024+1)
   if len(raw)>4*1024*1024:raise ValueError('Oversized tool response')
   return json.loads(raw)
  def safe_get(self,*args,**kwargs):raise ValueError('Not an execution preset')
 setup_mcp_server(ScopedClient()).run(transport='stdio')

async def dispatch(value):
 from mcp import ClientSession, StdioServerParameters
 from mcp.client.stdio import stdio_client
 async with stdio_client(StdioServerParameters(command=sys.executable,args=[str(Path(__file__).resolve()),'--serve'],env={'HEXSTRIKE_PORT':os.environ.get('HEXSTRIKE_PORT','8888')})) as (read,write):
  async with ClientSession(read,write) as session:
   await session.initialize()
   if value['operation']=='list':
    values=[];cursor=None
    while True:
     page=await session.list_tools(cursor=cursor)
     values.extend(dict(name=t.name,description=t.description or '',inputSchema=t.inputSchema) for t in page.tools)
     cursor=page.nextCursor
     if not cursor:return values
   if value['operation']!='call':raise ValueError('Invalid operation')
   result=await session.call_tool(value['name'],arguments=value['arguments'])
   if result.isError:raise ValueError('MCP tool error')
   if result.structuredContent is not None:
    data=result.structuredContent
    return data['result'] if set(data)=={'result'} and isinstance(data['result'],dict) else data
   parts=[c.text for c in result.content if c.type=='text']
   return json.loads(''.join(parts))

if __name__=='__main__':
 if '--serve' in sys.argv:serve()
 else:print(json.dumps(asyncio.run(asyncio.wait_for(dispatch(json.load(sys.stdin)),310))))
