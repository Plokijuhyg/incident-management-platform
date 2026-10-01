# Incident Platform frontend

Angular 22 standalone SPA with signals, zoneless change detection, strict TypeScript/templates,
plain CSS and Vitest. Feature pages are loaded lazily.

## Run locally

From the repository root, start the configured backend (MySQL and user secrets must be ready):

```powershell
dotnet run --project backend/IncidentPlatform.Api --launch-profile https
```

In a second terminal:

```powershell
cd frontend
npm ci
npm start
```

Open http://localhost:4200. Sign in with an existing account; the UI does not create a default user.
The development proxy forwards `/api/**` to `https://localhost:7146`. Its `secure: false` setting
is only for the local ASP.NET development certificate. Adjust `proxy.conf.json` if the API port changes.

## Implemented

- Login with reactive validation, generic authentication failure messages, and return navigation.
- In-memory JWT state, single shared refresh request after a reload using the HttpOnly cookie,
  guarded routes and API-scoped JWT interception. API 401 responses clear state and redirect to login.
  An expired session requires signing in again; requests are not automatically replayed.
- Logout revokes the refresh cookie before clearing local state; failure can be retried.
- Incident register with server pagination, refresh, loading, error and empty states.
- Incident detail with safe text rendering, classification, assignee and recorded milestones.
- Incident creation with numeric enums, field validation and local-to-UTC time conversion.
- Incident editing with optimistic concurrency: a 409 preserves the draft until the user
  explicitly loads the latest record. Assigned analysts, managers and admins can edit/change status.
  Managers and admins can assign an active owner or close with a required resolution summary.
- Evidence listing, multipart uploads, authenticated downloads, SHA-256 display and confirmed
  deletion for managers/admins. Unsupported or empty files are rejected locally; the API enforces
  MIME and size limits. Downloads use the JWT interceptor rather than unauthenticated links.
- Admin-only user directory with pagination, account creation, profile editing, role assignment
  and confirmed deactivation. Self-deactivation and removing one's own Admin role are blocked.
- Dashboard with workspace counters, severity/status/category and IOC charts, MITRE rankings,
  daily/weekly line charts, and MTTD/MTTC/MTTR with contributing sample counts and
  an explicit caution for samples smaller than five. Period choices are
  7, 30 and 90 days; only trends and response metrics use this period. Missing metrics show
  "No data" while a measured zero remains zero. Charts include readable counts/data tables.
- Refreshed dashboard and responsive workspace with icon navigation, a page finder, quick links,
  live API charts, and clear loading/error/empty states.
- Alerts with source/status filters, creation, evidence payload review, false-positive triage and
  promotion to incidents (including PenTest source).
- IOC catalog with search/filters, exact lookup, creation and confidence/verdict editing;
  asset catalog with manager/admin creation and editing; MITRE catalog with tactic/search filters.
- Incident investigation workspace: comments, timeline, response-action records/outcomes, and
  adding/removing IOC, asset and MITRE associations. Unlinking preserves the catalog record.
- Admin audit browser with filters and pagination; account page with password change.
- Admin lab connection settings/status checks for configured HexStrike and Ollama services.

The current incident list endpoint implements only `page` and `pageSize`; filtering/search/sorting
controls await API support. MITRE is a reference catalog, not an editor. Account reactivation
and administrator password reset are not exposed by the user-management endpoints.

## Local lab configuration

Configure URLs on the API server (restart after changes):

```powershell
dotnet user-secrets set "Lab:HexStrikeUrl" "http://127.0.0.1:8888" --project backend/IncidentPlatform.Api
dotnet user-secrets set "Lab:OllamaUrl" "http://127.0.0.1:11434" --project backend/IncidentPlatform.Api
```

The defaults use loopback **on Windows where the API runs**. Kali's loopback is a different
machine; a private authenticated tunnel to Kali is needed to use that default HexStrike URL.
Alternatively configure the verified private lab address after securing that connection.
Checks query `/health` and `/api/tags`, use a five-second timeout, reject public destinations
and redirects, and never execute commands or models. No check runs automatically.

LLM installation is deferred. The separate Assessments page provides a persisted job queue
and a service-inventory profile, with execution disabled until Laptop 2 is configured.
MCP sessions, vulnerability scan profiles and report generation remain unimplemented.
PenTest alerts can hold externally collected results and be promoted into incidents.

## Verify

```powershell
npm run build
npm test -- --watch=false
npm run test:browser
```

Tests cover auth, admin guards, token origin restrictions, session expiration, pagination/cancellation,
validation, incident creation and actions, concurrency conflicts, evidence upload/download/delete,
user access controls, preservation of form drafts, reporting periods, and missing/zero metrics.
HTTP tests use Angular's test backend; no real credentials or database are needed.

`test:browser` runs headless Chrome/Edge against the production build with API fixtures.
It verifies protected deep links, login, list/detail/create/edit/assign/status/close workflows,
evidence upload/download/delete, dashboard reporting periods, user creation/profile/roles/deactivation,
alert promotion, investigation comments/tabs, IOC/asset/MITRE detail, audit browsing, lab checks,
account navigation, admin route restrictions, mobile layouts, JWT requests and logout. Screenshots and fixture downloads
are saved in `frontend/dist/`. It uses an
isolated browser profile under `dist/`; no personal browser session is accessed.
Set `BROWSER_PATH` if the browser is not installed at a standard location.
This is a browser smoke test with fixtures, not an end-to-end test against live MySQL.

## Deployment

Serve `dist/incident-platform/browser` over HTTPS, route `/api` to the backend on the same origin,
and fall back to `index.html` for frontend deep links. Preserve Set-Cookie and cookie paths at the proxy.
The Angular development proxy is not used by production builds. Apply SPA-appropriate security
headers at the frontend host: the backend API's `default-src 'none'` CSP is unsuitable for the SPA.
The API remains responsible for every authorization decision.

## Windows telemetry and assessments

Windows Events shows actual collected events, per-channel coverage/errors, filtering, raw XML and rule-linked alerts. The collector runs on the Windows API host; Security-channel permissions must be granted separately. It retains seven days by default and starts with a five-minute lookback, then resumes stored bookmarks. Configuration: `WindowsEvents:Enabled`, `PollSeconds`, `RetentionDays`, `InitialLookbackMinutes`.

Assessments provides approved-target selection, real gateway capability checks, persisted execution history, raw evidence and service observations. Laptop 2 is not ready: `HexStrike:Enabled` stays false and targets stay empty. See `integrations/hexstrike/README.md` and `docs/siem-feature-coverage.md` for capabilities and remaining gates.

From the repository root, `npm start` now launches Angular; `npm run start:api` launches the backend. Automated tests remain available but use separate test data.

## Live dashboard operation

The dashboard now displays real Windows ingestion counts, average events/second over the last 60 seconds, a 30-minute ingestion chart, top channels and the latest 10 events. It refreshes every five seconds while visible. Incident summaries, charts and the latest 10 incidents refresh every 15 seconds. The incident register contains all incidents with pagination. Counters change only when the underlying data changes; no synthetic animation or incidents are generated.

Keep MySQL and the Windows backend running (`npm run start:api` from the repository root). Opening the browser alone does not start collection. The backend continues collecting when the browser is closed; this development setup is not installed as an automatically starting Windows service. Start Angular with `npm start`, then open http://localhost:4200/dashboard. Admin and Security Manager accounts can see raw Windows telemetry. Other analysts retain incident dashboard access.

If protected channels report Access denied, stop the existing backend with Ctrl+C, then run the backend command in a PowerShell window opened as Administrator for local development. Do not start a second backend on the same port. A persistent deployment should use a dedicated account with the necessary Event Log read permissions instead. Channel errors are visible under Windows Events; Windows auditing must already be enabled to generate the relevant events. The app does not enable audit categories or disabled channels automatically.

Logs do not all become incidents. The four current detection rules cover Security log clearing (1102), account creation (4720), local group membership addition (4732), and Defender detection (1116), matched to their expected providers/channels. Review generated alerts in Alerts and promote those requiring investigation. No manual step is needed for routine ingestion once the backend and database are running. A zero incident count is valid when no incidents have been recorded.

## Automation and standards coverage

Open `/automation` as Admin or Security Manager to inspect the four Microsoft-documented Windows detection policies, their source references, control mappings and immutable decision history. Policies start in Observe; an Admin can select an active owner and AutoPromote for Defender detection or audit-log clearing. Changes affect future alerts only. No AI or Kali connection is needed. See `docs/detection-automation-and-standards.md` for behavior, validation and remaining ISO/CIS Benchmark assessment requirements.

## SOC workspace views

The reference-inspired compact UI adds `/overview`, `/analytics`, `/attack-matrix`, `/tasks` and `/resources`. Overview and MITRE counts come from real incident associations; Analytics queries collected Windows events. CMDB opens the asset catalog. Read `docs/soc-workspace-ui.md` for data scope and explicit unsupported screenshot features.
