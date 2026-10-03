# SIEM feature coverage - 2026-09-26

This maps executable product capabilities to UI entry points. Test code, migrations, validators and middleware support the product; they are not separate product screens. Test fixtures are excluded from the application database and production bundle.

| Implemented backend area | Application entry point |
| --- | --- |
| Login/refresh/logout/password change | Login, account, shell session controls |
| Incident list/create/detail/edit/assign/status/close | Incidents and incident actions |
| Comments/timeline/response actions | Incident investigation workspace |
| IOC/asset/MITRE incident associations | Investigation tabs; catalog records retain their identity after unlinking |
| Evidence list/upload/download/delete | Incident evidence panel |
| Alert creation/triage/promotion | Alerts |
| IOC search/filter/lookup/create/update | Indicators |
| Asset list/create/update | Assets; manager/admin write controls |
| MITRE tactics/search/reference detail | MITRE ATT&CK |
| User directory/create/profile/roles/deactivate | Users, administrator only |
| Dashboard SQL counts, trends and metrics | Dashboard: incident metrics refresh every 15 seconds; real Windows activity, ingestion chart and latest events every 5 seconds; latest incidents link to the complete register |
| Global and incident-scoped audit | Audit trail for admins; incident audit history for managers/admins |
| Windows event collection and native XML | Windows Events, managers/admins; channel errors and coverage shown |
| Generic log ingestion (syslog/firewall/VPN/API) → parse → normalize → enrich → detect | Logs page (managers/admins); `POST /api/logs/ingest` with a pre-shared key; IOC enrichment and built-in rules raise alerts |
| Alert correlation → automatic case creation | Background `CorrelationEngine`: groups related alerts by entity into Tier-1 cases (`IncidentSource.Correlation`); no UI action needed |
| Case workflow: Tier 1/2/3, SLA targets, escalation | Incidents page (Tier column/filter, SLA breach badge) and incident detail (Escalate action); `POST /api/incidents/{id}/escalate` |
| UEBA: per-user baselines and anomaly alerts | UEBA page (managers/admins); `GET /api/ueba/entities`; failed-login spike and new-source-IP anomalies feed correlation. Baselines fold from both the ingested `LogEvents` store and live Windows sign-ins (4624/4625); forward-looking, no backfill |
| HexStrike/Ollama health checks | Lab connections; health is not proof of assessment readiness |
| Rule-based incident automation and standards evidence | Automation & coverage: versioned policies, observed/promoted decisions, NIST/CIS/ISO support and explicit benchmark gaps |
| Curated detection baseline (enable supported High/Critical rules, suppress noise) | Automation & coverage → Detection baseline: one-click apply in Observe mode; `GET`/`POST /api/detection-rules/baseline`. Excludes Sysmon-only rules (no Sysmon channel collected) |
| Persisted assessment queue/history/evidence | Assessments; remote execution disabled until Laptop 2 is ready |
| Offline HexStrike tool catalog (supported tools by category/tier) | Assessments → Supported tools; `GET /api/assessments/catalog`. Visible before the gateway connects; 21 reviewed/runnable, rest advertised-for-planning |
| Assessment target by typed private lab IP or saved target | Assessments → Choose a target: a **Lab target IP** field (RFC1918 only; public IPs refused server-side) plus the saved-target picker. `POST /api/assessments/scan` with `targetIp` |
| LLM analysis of assessment evidence (defensive brief and authorized-lab exploitation walkthrough) | Assessments → Inspect assessment → Local model analysis: a mode switch requests a defensive SOC brief or an educational lab exploitation walkthrough; `POST /api/assessments/{id}/analysis` with `mode`. Bounded normalized evidence only; local Ollama; deferred until a model is installed |
| Readiness, rate limiting, security headers, validation | Enforced API infrastructure, not manual UI actions |

## Real telemetry versus fixtures

The local Windows collector is enabled in user secrets. It reads the API host's enabled Event Log channels, persists cursors and deduplicates by fingerprint. UI refresh is every three seconds; collection uses two seconds between full sweeps, so it is near-real-time rather than a guaranteed fixed latency. Initial coverage starts five minutes before first discovery, not the entire historical log archive. Retention defaults to seven days and is configurable.

Security and other protected channels may be denied under a standard Windows user. They are reported explicitly. Run the local API with suitable Event Log permissions when complete channel coverage is required; the application does not silently change audit policies or OS privileges. Disabled audit categories and arbitrary application text files are not collected. Detection currently uses four explicit rules; ordinary events do not become incidents automatically.

Test isolation: integration tests target `incident_management_tests`. The prior fixture alerts/incidents/assets were removed after a full ignored local backup. Eleven proven test accounts are disabled but retained for attribution dependencies; audit history is preserved. Browser and Python fixtures live only in test tools, never in the user-facing application data.

## Remaining real-world gates

- Provision and verify Laptop 2, its management address, certificates, HexStrike installation and approved isolated target. No live remote assessment is claimed.
- Current assessment profile is service inventory only. Vulnerability profiles, explicit intrusive-action approvals, running-job termination, normalized PenTest alert creation and report exports remain future work; the UI states those limits.
- Ollama/model installation and evidence-grounded analysis remain deferred by the user.
- A full enterprise SIEM would additionally need independently scoped retention sizing, broader ingestion sources, correlation rules, alert tuning and operational deployment validation. This repository is not certified as a complete commercial SIEM.
