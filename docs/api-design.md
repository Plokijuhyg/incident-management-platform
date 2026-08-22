# API Design

> **Status:** DESIGN — agreed 2026-08-22. No endpoint is implemented yet.
> This file is the contract for both the ASP.NET Core controllers and the Angular
> `core/services`. Endpoints get marked ✅ as they are built and verified.

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

**`GET /api/incidents` filters:** `status`, `severity`, `priority`, `category`,
`source`, `assignedToId`, `createdById`, `unassigned=true`, `detectedFrom`,
`detectedTo`, `createdFrom`, `createdTo`, `search` (title + incident number +
description), `iocValue`, `assetId`, `mitreTechniqueId`.

List items are a **summary** projection (no descriptions, no child collections) —
selected with `.Select()` so the SQL fetches only those columns. Loading full
aggregates for a 25-row table is the classic full-stack performance mistake.

`PUT` requires the `version` field from the last GET; a mismatch returns `409`
rather than overwriting a concurrent edit.

`POST /api/incidents/{id}/status` body: `{ "status": "CONTAINED", "note": "..." }`.
Automatically writes a timeline event and sets the matching milestone timestamp —
so the timeline can never drift from the status. Illegal transitions return `422`
once the state machine is designed (Phase 8).

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
| GET | `/api/alerts` | All | Filters: `status`, `source`, `severity`, `detectedFrom/To`, `search`, `unpromoted=true` |
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

## 8. Audit logs — `/api/audit-logs`

| Method | Route | Roles |
|---|---|---|
| GET | `/api/audit-logs` | Admin only |
| GET | `/api/audit-logs/entity/{entityType}/{entityId}` | Admin, Manager |

Filters: `actorUserId`, `action`, `entityType`, `outcome`, `from`, `to`,
`ipAddress`. Read-only by design — no POST, PUT, or DELETE exists at any route.

---

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
