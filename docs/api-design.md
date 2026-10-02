# API Design

> **Status:** Users management, audit writes, dashboard endpoints, rate limiting,
> readiness and security headers implemented (2026-09-24).
> Other sections retain their design requirements unless explicitly marked below.

**Base URL:** `/api` · **Format:** JSON · **Auth:** `Authorization: Bearer <jwt>`
· **Time:** all timestamps ISO 8601 UTC (`2026-08-22T14:03:11Z`)

---

## 1. Conventions

### Resource identity

Routes use the internal `Id`, not the display number: `/api/incidents/42`, not
`/api/incidents/INC-2026-000042`. The display number is a formatting concern and
is returned in the payload. Lookup by number is a filter, not a route.

### Status codes

| Code | Used for |
|---|---|
| 200 | Successful GET / PUT |
| 201 | Successful POST, with `Location` header |
| 204 | Successful action with no body |
| 400 | Validation failure |
| 401 | Missing / invalid / expired token |
| 403 | Authenticated but not permitted |
| 404 | Not found **or** not visible to this caller (see `security.md` on IDOR) |
| 409 | Conflict — concurrency token mismatch, duplicate unique value |
| 413 | Upload too large |
| 415 | Unsupported media type |
| 422 | Semantically invalid (e.g. illegal status transition) |
| 429 | Rate limit exceeded, with `Retry-After` |
| 500 | Unhandled — opaque body, details only in server logs |

### Error shape — RFC 7807 `ProblemDetails`, always

```json
{
  "type": "https://httpstatuses.io/400",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "detail": "See errors for details.",
  "instance": "/api/incidents",
  "traceId": "0HN7...",
  "errors": {
    "Title":    ["Title is required.", "Title must be 200 characters or fewer."],
    "Severity": ["'EXTREME' is not a valid severity."]
  }
}
```

One error shape for every failure means the Angular error interceptor is written
once. `traceId` correlates a user-reported failure with server logs without
leaking internals. Exception messages and stack traces are **never** in the
response in Production.

### Pagination — every collection endpoint

Request: `?page=1&pageSize=25` (1-based; `pageSize` capped at **100** server-side
— an uncapped page size is a denial-of-service vector).

Response envelope:

```json
{
  "items": [ ... ],
  "page": 1,
  "pageSize": 25,
  "totalCount": 347,
  "totalPages": 14,
  "hasNextPage": true,
  "hasPreviousPage": false
}
```

Offset pagination, not cursor: the UI needs jump-to-page and total counts, and at
this data volume `LIMIT/OFFSET` is fine. Revisit if a table ever exceeds ~100k rows.

### Sorting

`?sortBy=detectedAt&sortDirection=desc`. `sortBy` is validated against an
**allow-list per endpoint** and mapped to a column in code — never interpolated
into SQL, and never used to sort by a column the caller shouldn't know exists.
Default: `createdAt desc`.

### Filtering

Repeated query parameters mean OR within a field, AND across fields:
`?status=NEW&status=TRIAGED&severity=CRITICAL` → *(NEW or TRIAGED) and CRITICAL*.

Unknown parameters are ignored, not errors — so adding a filter never breaks an
older client.

---

## 2. Authentication — `/api/auth`

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | Anonymous | Email + password → tokens |
| POST | `/api/auth/refresh` | Refresh token | New access token |
| POST | `/api/auth/logout` | Authenticated | Revoke refresh token |
| GET | `/api/auth/me` | Authenticated | Current user + roles |
| POST | `/api/auth/change-password` | Authenticated | Requires current password |

`POST /api/auth/login` — request:

```json
{ "email": "analyst@soc.local", "password": "..." }
```

Response `200`:

```json
{
  "accessToken": "eyJ...",
  "expiresIn": 900,
  "user": {
    "id": 7,
    "email": "analyst@soc.local",
    "fullName": "Sam Okafor",
    "roles": ["SOC_ANALYST"]
  }
}
```

Failure is always `401` with the same generic message for unknown-email,
wrong-password, and locked-account — distinguishing them is a user-enumeration
oracle. Rate limited hard (see §9). The refresh token is delivered as an
**HttpOnly, Secure, SameSite=Strict cookie**, not in the JSON body, so XSS cannot
read it.

---

## 3. Incidents — `/api/incidents`

| Method | Route | Roles | Description |
|---|---|---|---|
| GET | `/api/incidents` | All | Paged, filtered list |
| POST | `/api/incidents` | All | Create |
| GET | `/api/incidents/{id}` | All | Full detail with related collections |
| PUT | `/api/incidents/{id}` | All¹ | Update core fields |
| POST | `/api/incidents/{id}/assign` | Manager, Admin | Assign to an analyst |
| POST | `/api/incidents/{id}/status` | All¹ | Change status |
| POST | `/api/incidents/{id}/close` | Manager, Admin | Close, requires resolution summary |

¹ Analysts may modify incidents assigned to them; managers and admins, any.
Enforced in the service layer, not the route.

**`GET /api/incidents` filters (implemented):** `status`, `severity`, `priority`,
`category`, `source`, `assignedToId`, `unassigned=true` (not combinable with
`assignedToId`), `openOnly=true` (excludes Resolved, Closed, FalsePositive),
`createdFrom`, `createdTo`, `search` (title + incident number + description, max 200).
Sorting: `sort` = `createdAt` (default) | `updatedAt` | `severity` | `priority` |
`status` | `title` | `incidentNumber`, `direction` = `asc` | `desc`. Enum sorts follow
severity/workflow order, not alphabetical; ties break on newest id. Unknown sort keys
return `400`. Still planned: `createdById`, `detectedFrom/To`, `iocValue`, `assetId`,
`mitreTechniqueId`.

List items are a **summary** projection (no descriptions, no child collections) —
selected with `.Select()` so the SQL fetches only those columns. Loading full
aggregates for a 25-row table is the classic full-stack performance mistake.

`PUT` requires the `version` field from the last GET; a mismatch returns `409`
rather than overwriting a concurrent edit.

`POST /api/incidents/{id}/status` body: `{ "status": "CONTAINED", "note": "..." }`.
Automatically writes a timeline event and sets the matching milestone timestamp —
so the timeline can never drift from the status. `Closed` is rejected with `400`:
closing goes through `/close`, which is Manager/Admin only and requires a resolution
summary. Reopening a closed incident is likewise Manager/Admin only (`403` otherwise)
and clears `closedAt`. Assign, status and close return `409` if another request
modified the incident concurrently. Other illegal transitions return `422` once the
state machine is designed (Phase 8).

---

## 4. Incident sub-resources

Child collections are nested under the incident, because they have no independent
existence and their authorization is inherited from the parent.

| Method | Route | Roles | Notes |
|---|---|---|---|
| GET / POST | `/api/incidents/{id}/comments` | All | `PUT`/`DELETE` on `/comments/{cid}`: author or admin only |
| GET / POST | `/api/incidents/{id}/timeline` | All | Sorted by `occurredAt`; no delete — the record is the point |
| GET / POST | `/api/incidents/{id}/response-actions` | All | `PUT` `/response-actions/{aid}` to update status/result |
| GET / POST | `/api/incidents/{id}/iocs` | All | POST links an IOC; creates the catalog entry if new |
| DELETE | `/api/incidents/{id}/iocs/{iocId}` | All | Unlinks only — never deletes the catalog entry |
| GET / POST | `/api/incidents/{id}/assets` | All | Link with `impactType` |
| DELETE | `/api/incidents/{id}/assets/{assetId}` | All | Unlink |
| GET / POST | `/api/incidents/{id}/mitre-techniques` | All | Link technique |
| DELETE | `/api/incidents/{id}/mitre-techniques/{tid}` | All | Unlink |
| GET / POST | `/api/incidents/{id}/evidence` | All | POST is `multipart/form-data` |
| GET | `/api/incidents/{id}/evidence/{eid}/download` | All | Streams the file |
| DELETE | `/api/incidents/{id}/evidence/{eid}` | Manager, Admin | Chain of custody — restricted |

`POST /api/incidents/{id}/iocs` accepts `{ type, value, confidence, role, notes }`
and performs the upsert described in `database-design.md` §3.1: normalise the
value, find-or-create the catalog entry, create the link, bump `SightingCount` and
`LastSeenAt` — all in one transaction. The response indicates whether the IOC was
newly created or already known, since "we've seen this before" is the answer the
analyst actually wants.

---

## 5. Alerts — `/api/alerts`

| Method | Route | Roles | Description |
|---|---|---|---|
| GET | `/api/alerts` | All | Filters: `status`, `source`, `severity` (source text, case-insensitive), `detectedFrom/To`, `search` (title, description, rule ID), `openOnly=true` (New + InReview). Sort: `detectedAt` (default) \| `severity` \| `status` \| `source` \| `title`, `direction` = `asc` \| `desc` |
| POST | `/api/alerts` | All | Manual alert creation |
| GET | `/api/alerts/{id}` | All | Detail including `rawPayload` |
| POST | `/api/alerts/{id}/promote` | All | → incident |
| POST | `/api/alerts/{id}/false-positive` | All | Close with a required reason |
| POST | `/api/alerts/{id}/assign-to-incident` | All | Link to an **existing** incident |

`POST /api/alerts/{id}/promote` is the workflow hinge. Body carries the incident
fields to seed (`title`, `severity`, `priority`, `category`); it creates the
incident, links the alert, sets the alert to `PROMOTED`, and writes an
`ALERT_RECEIVED` timeline event with `occurredAt` = the alert's `detectedAt` — one
transaction, or none of it. Returns `201` with the new incident.

---

## 5a. Log ingestion — `/api/logs`

The generic (non-Windows) ingestion pipeline: **Raw → Parse → Normalize → Enrich → detect**.
Every ingested line becomes a `LogEvent` on one common schema and UTC timeline, so syslog,
firewall, VPN and API feeds are jointly queryable and feed the same alert path.

| Method | Route | Roles | Description |
|---|---|---|---|
| POST | `/api/logs/ingest` | Ingest key | Anonymous; gated by `X-Ingest-Key` (SHA-256 in `Ingestion:Keys`), HTTPS-only, off unless `Ingestion:Enabled`. Body `{ source, format, lines[] }`; `format` = `Syslog`\|`Firewall`\|`Vpn`\|`Json`\|`KeyValue`. Returns `{ accepted, duplicates, alerts, blank }`. Deduplicates by fingerprint; rejections audited |
| GET | `/api/logs` | Admin, Manager | Filters: `source`, `sourceType`, `maxSeverity` (0 worst … 7), `action`, `outcome`, `ip` (src or dst), `user`, `search` (message), `from`/`to` (event time), `alertsOnly=true`. Sort: `eventTime` (default) \| `receivedAt` \| `severity` \| `source` |
| GET | `/api/logs/{id}` | Admin, Manager | Detail incl. raw line, parsed fields, enrichment |
| GET | `/api/logs/summary` | Admin, Manager | Store totals, last-hour volume, alerts raised, per-source stats |

Parsers: syslog RFC 5424 and RFC 3164 (3164 has no year/zone — current UTC year assumed);
firewall/VPN key-value lifted from the syslog message; JSON objects. Normalization maps vendor
aliases (`src`/`srcip`/`saddr` → source IP, etc.) and converts timestamps to UTC. **Enrich**: source
and destination IPs are matched against malicious IOCs; a hit raises a High `LOG-IOC-MATCH` alert.
Built-in rules also cover `VPN-AUTH-FAILURE` and `LOG-CRITICAL-SEVERITY`. Correlation/threshold rules
across many events are a later increment; automation auto-promote still applies to Windows alerts only.

---

## 6. IOCs, Assets, MITRE, Users

| Method | Route | Roles | Description |
|---|---|---|---|
| GET | `/api/iocs` | All | Filters: `type`, `confidence`, `isMalicious`, `search`, `minSightings` |
| POST | `/api/iocs` | All | Create catalog entry directly |
| GET | `/api/iocs/{id}` | All | Detail **+ every incident it appeared in** — the correlation payoff |
| PUT | `/api/iocs/{id}` | All | Update confidence / verdict / description |
| GET | `/api/iocs/lookup?type=&value=` | All | "Have we seen this?" — the single most useful endpoint in the app |
| GET / POST | `/api/assets` | All / Manager+Admin | List / create |
| GET / PUT | `/api/assets/{id}` | All / Manager+Admin | Detail + incident history / update |
| GET | `/api/mitre/techniques` | All | Filters: `tactic`, `search`, `includeSubTechniques` |
| GET | `/api/mitre/techniques/{techniqueId}` | All | By `T####` string |
| GET | `/api/mitre/tactics` | All | Distinct tactics, for grouped UI |
| GET / POST | `/api/users` | Admin | List / create |
| GET / PUT | `/api/users/{id}` | Admin² | Detail / update |
| POST | `/api/users/{id}/deactivate` | Admin | Never a hard delete |
| POST | `/api/users/{id}/roles` | Admin | Replace role assignments |
| GET | `/api/roles` | Authenticated | Reference list for pickers |
| GET | `/api/users/assignable` | All | Slim list for assignee dropdowns — no PII beyond id + name |

² A user may read and update their own profile via `/api/auth/me`, not via
`/api/users/{id}`.

`GET /api/users/assignable` exists so that populating an assignee dropdown does
not require analysts to have permission on the full admin user list.

---

## 7. Dashboard — `/api/dashboard`

| Method | Route | Description |
|---|---|---|
| GET | `/api/dashboard/summary` | Headline counters |
| GET | `/api/dashboard/incidents-by-severity` | Grouped counts |
| GET | `/api/dashboard/incidents-by-status` | Grouped counts |
| GET | `/api/dashboard/incidents-by-category` | Grouped counts |
| GET | `/api/dashboard/incidents-over-time?days=30&interval=day` | Time series |
| GET | `/api/dashboard/top-ioc-types` | Grouped counts |
| GET | `/api/dashboard/top-mitre-techniques?limit=10` | Ranked |
| GET | `/api/dashboard/metrics` | MTTD / MTTC / MTTR |

Every figure is computed by SQL aggregation in the database — `GROUP BY` and
`COUNT`, not entities loaded into memory and counted in C#. **No dashboard number
is ever hard-coded or faked in the frontend**; the Angular components render
whatever the API returns and nothing else.

`/api/dashboard/summary`:

```json
{
  "totalIncidents": 347,
  "openIncidents": 42,
  "criticalOpenIncidents": 3,
  "unassignedIncidents": 7,
  "newAlerts": 18,
  "incidentsCreatedToday": 5,
  "myOpenIncidents": 6
}
```

`/api/dashboard/metrics` — the three metrics the milestone timestamps of
`database-design.md` §4.3 exist to support:

```json
{
  "meanTimeToDetectMinutes": 34.2,
  "meanTimeToContainMinutes": 187.5,
  "meanTimeToResolveMinutes": 1432.8,
  "sampleSize": 128,
  "periodDays": 30
}
```

`sampleSize` is included because an average over four incidents is not a metric,
and the UI should be able to say so. These are the first endpoints to get Redis
caching (Phase 27) — expensive aggregates, tolerant of a short TTL.

---

### Implemented dashboard semantics

All dashboard routes require authentication and have organization-wide visibility,
matching the existing incident list. `myOpenIncidents` uses the authenticated user.
Open excludes `Resolved`, `Closed`, and `FalsePositive`; unassigned counts only open incidents.
Grouped responses use `{ label, count }`; MITRE ranking uses `{ techniqueId, name, count }`.

Time series use UTC `CreatedAt`, include today, and fill missing buckets with zero.
`days` is 1?365; `interval` is `day` or `week`. Weeks are consecutive seven-day
buckets anchored at the start of the requested range (the last may be partial).
Each item is `{ start, count }`. SQL performs grouping for both intervals.
MITRE `limit` is 1?100 (default 10). Invalid bounds return 400.

Metrics accept `periodDays=30` (1?365) and select incidents created during the
rolling period. Durations are SQL averages in minutes:

- MTTD: `DetectedAt - OccurredAt`. `OccurredAt` is an optional incident-create
  field; when supplied it requires `DetectedAt >= OccurredAt`.
- MTTC: `ContainedAt - DetectedAt`.
- MTTR: `ResolvedAt - DetectedAt`.

Unknown milestones and negative durations are excluded separately for each metric.
An empty metric returns `null`, not zero. `sampleSize` counts incidents in the period;
`detectionSampleSize`, `containmentSampleSize`, and `resolutionSampleSize` report
actual contributing samples. Existing rows have unknown occurrence time and do not
contribute to MTTD until that information exists; creation delay is not detection delay.

The UI displays the period `sampleSize` and each metric's contributing sample count.
A nonzero contributing sample smaller than five shows a small-sample caution; this is
an explicit presentation threshold, not a statistical significance claim. The time series
is a line chart with an accessible table of the same API values. Empty SQL buckets are
zero-filled; no incident entities are loaded to count in memory. Integration tests capture
executed MySQL commands and require SQL COUNT/GROUP BY for grouped results and AVG/COUNT
for metrics (ungrouped headline totals use SQL COUNT directly).

---

## 8. Audit logs — `/api/audit-logs`

| Method | Route | Roles |
|---|---|---|
| GET | `/api/audit-logs` | Admin only |
| GET | `/api/audit-logs/entity/{entityType}/{entityId}` | Admin, Manager |

Filters: `actorUserId`, `action`, `entityType`, `outcome`, `from`, `to`,
`ipAddress`. Read-only by design — no POST, PUT, or DELETE exists at any route.

---

### Implemented audit writes

HTTP mutations write entity action records (`INCIDENT_CREATED`, `INCIDENT_UPDATED`,
`USERROLE_CREATED`, etc.) with generated entity IDs and field before/after values
in the same SQL transaction as their data changes. Values outside an explicit
allow-list are redacted; no passwords, tokens, raw payloads, file contents or storage
paths are recorded. Role links use composite IDs (`userId:roleId`).

Auth writes include `LOGIN_SUCCEEDED`, `TOKEN_REFRESHED`, `LOGOUT`, and
`PASSWORD_CHANGED`. Failure capture includes `LOGIN_FAILED`, `ACCESS_DENIED`
(outcome `Denied`), and `REQUEST_FAILED`, including rate-limit rejection.
Failed login email is a claimed identity; the actor ID remains null.
Evidence actions are `EVIDENCE_UPLOADED`, `EVIDENCE_DOWNLOADED`, and `EVIDENCE_DELETED`.
Download is audited before streaming: the record means access was granted, not
that the client received every byte. Failed requests use a separate database scope
so pending business changes cannot be accidentally committed.

## 9. Rate limiting

ASP.NET Core's built-in rate limiter, per-policy, keyed by IP for anonymous
endpoints and by user id once authenticated. Exceeding a limit returns `429` with
`Retry-After`.

| Policy | Applies to | Limit |
|---|---|---|
| `login` | `POST /api/auth/login` | 5 / 15 min per IP+email — brute-force defence |
| `upload` | Evidence POST | 20 / hour per user |
| `search` | List endpoints with `search` | 60 / min per user |
| `global` | Everything else | 300 / min per user |

---

Policies are fixed-window, in-process ASP.NET Core limiters, shared across all
routes within each policy for a user. Login email is trimmed and lowercased, then
hashed for the IP+email partition. Login JSON is bounded to 16 KiB before parsing.
Authenticated policies use the validated user ID; anonymous callers use the socket
IP. Forwarding headers are not trusted automatically. Each request consumes its
specific policy or the global policy. Health probes are exempt. Multi-instance
deployment requires a shared/edge limiter to enforce cluster-wide budgets.

## 10. Health & docs

| Route | Purpose |
|---|---|
| `/health` | Liveness — is the process up |
| `/health/ready` | Readiness — MySQL reachable, later Redis |
| `/swagger` | OpenAPI UI, **non-Production only** |

`/health` returns no dependency detail to anonymous callers; a health endpoint
that enumerates your infrastructure is reconnaissance.

---

## 11. Not in the MVP

Cursor pagination · bulk operations · webhooks · `PATCH`/JSON-Patch · API
versioning (single client, `/api/v1` added only when a breaking change is real) ·
GraphQL · SIEM ingestion endpoints · report export (PDF/CSV).

### Operational deployment

Apply `dotnet ef database update --project backend/IncidentPlatform.Api` before
starting this version (migration `AddIncidentOccurredAt`, nullable column only).
`/health` probes the process only. `/health/ready` probes MySQL with a five-second
check timeout and returns 200/503 with only `Healthy`/`Unhealthy` text.

Every API response gets CSP (`default-src 'none'`, no frames, base URI or forms),
`nosniff`, `DENY`, `no-referrer`, restricted device permissions and `Cache-Control:
no-store`. HTTPS redirection is enabled; HSTS is enabled outside Development.
Kestrel's Server header is disabled. The API does not serve the Angular SPA; its
hosting server needs its own browser-content policy.

User administration supports list/create/read/update, soft deactivation, replacing
roles, role reference data and slim active assignees. User creation and role links
commit atomically. Existing access tokens re-check active status and current roles
on every authenticated request; deactivation also revokes refresh tokens.
An administrator cannot deactivate themselves or remove their own Admin role.


### Workspace frontend completion (2026-09-25)

- `GET /api/incidents/{id}/iocs|assets|mitre-techniques`: authenticated association lists,
  returning catalog ID, name, reference, classification (role/impact), notes and added time.
  Missing incidents return 404. Existing POST/DELETE association endpoints are unchanged.
- `GET /api/audit-logs`: Admin only; page/pageSize (max 100), action substring,
  entityType/entityId exact match and numeric outcome filters. Newest events first.
- `GET /api/audit-logs/entity/{entityType}/{entityId}`: Admin or Security Manager; paginated.
- `GET /api/lab/connections`: Admin only; server-configured HexStrike/Ollama URLs.
- `POST /api/lab/connections/{hexstrike|ollama}/check`: Admin only; bounded health response,
  five-second timeout, literal loopback/RFC1918 destination only, no redirects or system proxy.
  Returns reachability, explanatory message and check timestamp; no scan/model execution.
- IncidentSource now includes PenTest (numeric 8), preserving existing enum values and allowing
  promotion of AlertSource.PenTest (numeric 6).
