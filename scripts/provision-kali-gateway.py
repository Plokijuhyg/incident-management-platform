"""Provision the confirmed private lab gateway over an already authenticated SSH connection.
Run on Windows. Secrets stay in ignored local state and .NET user secrets.
Does not submit a scan or change Windows certificate trust.
"""
import json, os, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = Path.home()/".ssh/incident_lab"
HOST = "kali@192.168.207.130"
REMOTE = "/home/kali/.local/share/incident-platform-gateway"
STATE = ROOT/"logs/hexstrike-private"

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def ssh(command, data=None):
    return run(["ssh", "-o", "BatchMode=yes", "-i", str(KEY), HOST, command], input=data, text=True)

REMOTE_SETUP = r'''
import os, json, secrets, subprocess
from pathlib import Path
os.umask(0o077)
r=Path.home()/".local/share/incident-platform-gateway"
r.mkdir(parents=True,exist_ok=True)
os.chdir(r)
def cmd(*args):
 subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
if not (r/"connection.json").exists():
 if (r/"ca.key").exists(): raise RuntimeError("Incomplete provisioning: inspect existing CA before retrying")
 cmd("openssl","req","-x509","-newkey","rsa:3072","-nodes","-keyout","ca.key","-out","ca.pem","-days","365","-subj","/CN=Incident Platform Lab CA","-addext","basicConstraints=critical,CA:TRUE,pathlen:0","-addext","keyUsage=critical,keyCertSign,cRLSign")
 for name,purpose in [("server","serverAuth"),("client","clientAuth")]:
  cmd("openssl","req","-newkey","rsa:2048","-nodes","-keyout",name+".key","-out",name+".csr","-subj","/CN=incident-platform-"+name)
  ext="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+purpose+"\n"
  if name=="server":ext+="subjectAltName=IP:127.0.0.1\n"
  Path(name+".ext").write_text(ext)
  cmd("openssl","x509","-req","-in",name+".csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial","-out",name+".pem","-days","90","-extfile",name+".ext")
 settings={"token":secrets.token_urlsafe(48),"password":secrets.token_urlsafe(32)}
 env=dict(os.environ,PFX_PASS=settings["password"])
 subprocess.run(["openssl","pkcs12","-export","-out","client.pfx","-inkey","client.key","-in","client.pem","-certfile","ca.pem","-passout","env:PFX_PASS"],env=env,check=True)
 Path("connection.json").write_text(json.dumps(settings))
else:settings=json.loads(Path("connection.json").read_text())
values={"GATEWAY_ENABLE_EXECUTION":"true","GATEWAY_BIND":"127.0.0.1","GATEWAY_PORT":"9443","GATEWAY_STORAGE":str(r/"state"),"APPROVED_TARGETS":'["192.168.207.129"]',"HEXSTRIKE_PORT":"8888","HEXSTRIKE_VERIFIED_VERSION":"6.0.0","GATEWAY_TOKEN":settings["token"],"GATEWAY_CERT":str(r/"server.pem"),"GATEWAY_KEY":str(r/"server.key"),"GATEWAY_CLIENT_CA":str(r/"ca.pem")}
Path("gateway.env").write_text("\n".join(k+"="+v for k,v in values.items())+"\n")
u=Path.home()/".config/systemd/user"
u.mkdir(parents=True,exist_ok=True)
(u/"incident-platform-gateway.service").write_text("[Unit]\nDescription=Incident Platform private lab gateway\n[Service]\nEnvironmentFile="+str(r/"gateway.env")+"\nExecStart=/usr/bin/python3 "+str(r/"gateway.py")+"\nRestart=on-failure\nUMask=0077\n[Install]\nWantedBy=default.target\n")
cmd("systemctl","--user","daemon-reload")
cmd("systemctl","--user","enable","--now","incident-platform-gateway.service")
cmd("systemctl","--user","restart","incident-platform-gateway.service")
print("Kali gateway user service configured; loopback only.")
'''

def main():
 # Refuse a broken module before changing the running Kali service.
 for filename in ["gateway.py", "vulnerability_checks.py", "scan_policy.py", "mcp_transport.py", "selected_scans.py"]:
  source=ROOT/"integrations/hexstrike"/filename
  compile(source.read_text(encoding="utf-8"),str(source),"exec")
 STATE.mkdir(parents=True,exist_ok=True)
 ssh("umask 077; mkdir -p "+REMOTE)
 run(["scp","-q","-i",str(KEY),str(ROOT/"integrations/hexstrike/gateway.py"),HOST+":"+REMOTE+"/gateway.py"])
 run(["scp","-q","-i",str(KEY),str(ROOT/"integrations/hexstrike/vulnerability_checks.py"),HOST+":"+REMOTE+"/vulnerability_checks.py"])
 run(["scp","-q","-r","-i",str(KEY),str(ROOT/"integrations/hexstrike/templates"),HOST+":"+REMOTE+"/"])
 for name in ["scan_policy.py", "mcp_transport.py", "selected_scans.py"]:
  run(["scp","-q","-i",str(KEY),str(ROOT/"integrations/hexstrike"/name),HOST+":"+REMOTE+"/"+name])
 ssh("python3 -", REMOTE_SETUP)
 for filename in ["ca.pem","client.pfx","connection.json"]:
  run(["scp","-q","-i",str(KEY),HOST+":"+REMOTE+"/"+filename,str(STATE/filename)])
 connection=json.loads((STATE/"connection.json").read_text())
 secrets_path=Path(os.environ["APPDATA"])/"Microsoft/UserSecrets/edfc24f8-0481-4fa1-96fc-bfc42f8cc29d/secrets.json"
 config=json.loads(secrets_path.read_text(encoding="utf-8-sig"))
 config.update({"HexStrike:Enabled":"true","HexStrike:GatewayUrl":"https://127.0.0.1:9443","HexStrike:GatewayToken":connection["token"],"HexStrike:ClientCertificatePath":str(STATE/"client.pfx"),"HexStrike:ClientCertificatePassword":connection["password"],"HexStrike:ServerCaCertificatePath":str(STATE/"ca.pem"),"HexStrike:Targets:0:Id":"metasploitable3","HexStrike:Targets:0:Name":"Metasploitable3 lab","HexStrike:Targets:0:Ip":"192.168.207.129","HexStrike:Targets:0:Approved":"true"})
 secrets_path.write_text(json.dumps(config,indent=2),encoding="utf-8")
 print("Backend user secrets configured. Start the 9443 tunnel and restart the API before verification.")
if __name__=="__main__":main()
