# SOC workspace UI

Implemented from the user-supplied FortiSIEM screenshots as a visual reference, keeping the IncidentSIEM identity and actual application data.

- Charcoal main navigation; orange active accents; compact white/gray tables; red/amber/green severity labels; responsive navigation and scrollable matrix/table panels.
- Dashboard: existing live Windows event activity and all original SQL incident metrics.
- Overview (`/overview`): incident creation-time range and open-state filter, SQL category counts, severity trend, affected assets from actual associations, title groups, latest 50 incidents and investigation links.
- Analytics (`/analytics`, Admin/Manager): bounded receive-time range, provider/host/message search, exact channel filter, SQL histogram and matching count, 100-row cursor pagination, escaped full original event XML. Refresh 15 seconds; older-page browsing pauses refresh.
- MITRE (`/attack-matrix`): loaded reference techniques/sub-techniques, explicit linked-incident counts, technique search, linked-only toggle, device/tactic associations and incident drill-down. Catalog presence is not detection coverage; counts do not claim prevention effectiveness. The existing reference catalog can be incomplete and is not advertised as the full latest ATT&CK release.
- CMDB navigation opens the existing asset inventory with create/edit/detail controls. No agent health or SNMP measurements are fabricated.
- Tasks (`/tasks`): all recorded response actions, status filter, 50-row pagination, owner/result/target and links to manage inside the incident workspace. These records do not execute endpoint commands.
- Resources (`/resources`): links to actual dashboards, indicators, investigations/evidence and reference data.

Live refresh only runs while the tab is visible. API failures retain prior results with an explicit stale-data notice. Raw telemetry remains restricted to Admin/Manager; existing server authorization remains authoritative.

Not implemented by this visual update: a separate cases module, arbitrary report designer/scheduler, UEBA, computed device risk scores, network traffic flows/bandwidth, SNMP performance, Fortinet product connectors, automated endpoint execution or full commercial-SIEM parity. These require independent data-source integrations and workflows; the screenshot fixture values are never inserted into the real database.

Validation: real MySQL tests cover overview/host association counts, technique drill-down, response tasks and filtered event histograms. Browser tests navigate each new screen and exercise raw-event/technique drill-down, alongside the existing incident actions, evidence, user management and mobile workflows. Browser data stays isolated in fixtures.
