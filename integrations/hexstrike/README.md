> Selectable MCP workflow: see [current implementation and limitations](../../docs/hexstrike-selectable-scans.md). The fixed-profile behavior below describes legacy execution/history. New UI requests use selected tools.

# Private Kali gateway

This is application-owned integration code, not an upstream HexStrike endpoint. It is **disabled by default** in repository configuration. The development lab has a separately provisioned Kali user service; real credentials and target approvals live in user secrets, never in this file. Python unit tests use isolated fixtures only.

Available profiles:
- `tcp-services`: TCP 1-1024 service inventory, informational observations.
- `vulnerability-checks`: bounded service discovery (1-1024 plus selected database,
  RDP and web ports), the Nmap `smb-vuln-ms17-010` detection script if 445 is open,
  then Nuclei and Nikto on up to four discovered HTTP endpoints. Nuclei uses only
  the two repository-owned GET templates (missing nosniff and exposed Git config).
  Nikto uses headers/paths plugins and JSON reporting, with update checks disabled.
  This is a selected check set, not a complete vulnerability scanner or all-CVE coverage.

Findings include source, endpoint, severity basis and original evidence. MS17-010
requires structured NSE `VULNERABLE` state and retains the script's High rating.
Template severities are local policy ratings, not invented CVSS scores. Nikto
observations remain Informational pending analyst severity triage. Duplicates
within a run are collapsed by tool/check/endpoint/title; cross-tool correlation is
not claimed. Tools with errors produce Partial/Failed outcomes, not a clean bill
of health. Running-job cancellation, exploitation, finding-to-alert promotion and
LLM analysis are not implemented. Only queued application jobs can be cancelled.

## Laptop 2 deployment gate

1. Verify the installed HexStrike server/version and real `/health` and `/api/tools/nmap` contract. Keep the server on Kali loopback. Review the fixed profile before authorizing its target.
2. Put Metasploitable on the isolated VM network; configure only its verified private address in both allowlists. Do not put the vulnerable VM on the management LAN.
3. Run the gateway as a restricted service account with a private writable state directory. HexStrike must be able to write the UUID-specific Nmap XML path in that directory; validate filesystem ownership on Kali before enabling execution.
4. Provision a dedicated lab CA, gateway server certificate with its management-IP SAN, and a Windows client certificate. The gateway requires mutual TLS **and** a random bearer token (minimum 32 characters). Trust only the intended CA for this lab; never disable certificate validation. The ASP.NET client uses platform trust by default. When `HexStrike:ServerCaCertificatePath` is set, trust is restricted to that dedicated CA for this HTTP client, while hostname, expiry and server-authentication checks remain enforced. The offline lab CA has no revocation endpoint; certificates expire after 90 days and must be renewed. Windows global certificate trust is unchanged.
5. Fill the environment variables listed in `gateway.env.example`. Bind to the private management address and firewall that port to Laptop 1 only. Set the exact inspected `HEXSTRIKE_VERIFIED_VERSION`; enable execution only after these checks.
6. Start `python3 gateway.py` under the chosen service manager. The final browser workflow does not require manually running scans or copying tool output. Initial service/network/certificate installation is still necessary.

Configure ASP.NET using environment variables or user secrets:

- `HexStrike:Enabled` (false by default)
- `HexStrike:GatewayUrl` (`https://<verified-private-management-IP>:9443`)
- `HexStrike:GatewayToken`
- `HexStrike:ClientCertificatePath` and `HexStrike:ClientCertificatePassword`
- `HexStrike:ServerCaCertificatePath` (optional dedicated private CA)
- `HexStrike:Targets:0:Id`, `Name`, `Ip`, `Approved`

Do not place real credentials in this repository. An empty target list and disabled integration remain the repository defaults; approved development targets are configured separately.

## Persistence and evidence

`POST /v1/jobs` accepts only `{id,target,profile}`. UUID reuse with different scope is rejected. SQLite persists jobs, one worker executes them, and a gateway restart marks in-flight jobs failed/unknown rather than executing again. The ASP.NET worker reconciles using the same UUID. A transport timeout never proves that a remote process stopped.

Each new job uses a unique, validated XML output filename so HexStrike command caching cannot satisfy it using an earlier job's output. A successful return code, no timeout and a newly written XML file are required; the API also validates the Nmap completion marker. Raw response/XML is retained, with a stored-response SHA-256 in MySQL. Oversized or malformed evidence is not accepted as a completed assessment. Local gateway files require operational retention/backup management before extended use.

The XML parser prohibits DTDs. It removes only Nmap's exact empty `<!DOCTYPE nmaprun>` line from the parsing copy; original evidence remains intact. Entity-bearing DTDs are rejected.

## Verification

```powershell
python -m unittest discover -s integrations/hexstrike -p test_gateway.py
```

These tests never contact Kali or scan any network. A real VMware lab run was validated on 2026-09-26; this does not establish a separate physical two-laptop deployment.

## Configured VMware development lab

Confirmed 2026-09-26: Kali `192.168.207.130`, Metasploitable3 `192.168.207.129`.
`scripts/provision-kali-gateway.py` provisions this specific lab using the existing
Windows SSH key `~/.ssh/incident_lab` (load it with `ssh-add` first). It creates a
loopback-only systemd **user** service on Kali, a dedicated CA and mTLS credentials,
and local development user secrets. It does not submit a scan. Private local files
are under ignored `logs/hexstrike-private`; protect them like credentials.

Start HexStrike on Kali as user `kali` so it can write the gateway's private result directory:

```bash
hexstrike_server --port 8888
systemctl --user status incident-platform-gateway
```

Keep this Windows tunnel running while using Assessments:

```powershell
ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -i "$env:USERPROFILE\.ssh\incident_lab" -L 127.0.0.1:9443:127.0.0.1:9443 kali@192.168.207.130
```

The separate port 8888 tunnel is used by Lab health diagnostics; Assessments uses
9443. Restart the API after provisioning to load the client certificate. Sign in
as Admin or SecurityManager, open Assessments, select Metasploitable3 and the TCP
service inventory profile. Service observations are not confirmed vulnerabilities.

The Kali user service is enabled for user sessions; startup before login and
Windows tunnel persistence after reboot are not configured. The provisioning
script reuses existing credentials; it does not renew expired certificates.

### Live validation, 2026-09-26

Application capabilities returned connected=true over mTLS. Assessment
`bf457876-bf41-4d08-96b7-ff17ef8c2809` completed against the approved target,
retaining original evidence and SHA-256. The bounded inventory observed TCP 135
(Microsoft RPC) and 445 (Microsoft SMB). These are informational service observations,
not validated vulnerabilities or full port coverage. Live testing exposed an HTTP
Content-Length mismatch; application JSON submissions now buffer the small body
before sending, with a dedicated transport regression test.

## Vulnerability evidence and limits

Raw per-tool files remain in the Kali job directory. API evidence previews are
bounded to 128 KiB per tool, with an explicit truncation marker and SHA-256 of the
complete text; tool stdout/stderr previews are also bounded. The application
retains the gateway response and its separate SHA-256. Failed tool evidence is
retained even when normalized findings cannot be trusted. No findings means no
matches from these checks, never proof of a secure host. Web redirects and Nuclei
out-of-band interactions are disabled. There is no brute forcing, payload upload,
exploit execution, authentication bypass or denial-of-service profile.

Run isolated parser/scope tests with:
`python -m unittest discover -s integrations/hexstrike -p "test*.py"`.

Vulnerability-profile validation on the configured Metasploitable3 lab detected
SMB MS17-010 (CVE-2017-0143, scanner risk High) and exercised Nuclei/Nikto against
the discovered HTTP API on TCP 5985. Results are scanner reports, not exploit
confirmation. Earlier Partial runs remain visible with their original errors;
new runs do not overwrite earlier evidence. Nikto 2.6 appends `.json` to its output
basename; this behavior is covered by the web-chain regression test.
