# Architecture

> **Status:** Backend operational controls implemented (2026-09-24): user management,
> transactional audit writes, SQL dashboard aggregation, rate limiting, readiness
> and security headers. Remaining planned features are noted in their sections.
> Update this file whenever the real architecture diverges from it.

---

## 1. System overview

```
                Browser
                   │  HTTPS
                   ▼
        ┌──────────────────────┐
        │  Angular SPA         │   static assets, no secrets, no auth decisions
        │  (frontend/)         │
        └──────────┬───────────┘
                   │  REST + JSON, JWT Bearer in Authorization header
                   ▼
        ┌──────────────────────┐
        │  ASP.NET Core Web API│   ← ALL authorization happens here
        │  (backend/)          │
        └──────────┬───────────┘
                   │  EF Core (Pomelo MySQL provider)
                   ▼
        ┌──────────────────────┐
        │  MySQL 8             │
        └──────────────────────┘

        Evidence files → private filesystem directory (MVP)
                       → object storage (later phase)
```

**Security boundary:** the API. The Angular app is untrusted — it runs on the user's
machine, its source is readable, and its route guards only exist to avoid showing
users doors they cannot open. Every request is authorized server-side on its own
merits, with no trust placed in anything the client asserts about who it is.

---

## 2. Backend layering

```
HTTP request
    │
    ▼
Middleware pipeline          cross-cutting: errors, logging, auth, rate limiting
    │
    ▼
Controller                   HTTP concerns only — bind, validate, map, return status
    │
    ▼
Service                      business logic, authorization rules, transactions
    │
    ▼
AppDbContext (EF Core)       persistence
    │
    ▼
MySQL
```

### Rules

- **Controllers contain no business logic.** A controller method should be short:
  accept a DTO, call one service method, translate the result to an HTTP status.
  No `DbContext` is ever injected into a controller.
- **Services never see HTTP types.** No `HttpContext`, `IActionResult`, or
  `ControllerBase` inside a service. The current user reaches services as an
  injected abstraction (`ICurrentUser`), not as a `ClaimsPrincipal` dug out of
  the request. This keeps services unit-testable without a web host.
- **Entities never cross the API boundary.** Requests and responses are DTOs.
  This is not ceremony — it is the mass-assignment and over-exposure defence
  (see `security.md`). An `Incident` entity carries navigation properties and
  internal fields a client must never set or see.
- **Async all the way down.** Every I/O path is `async`/`await` with
  `CancellationToken` threaded through, so an abandoned request stops doing work.

### On the Repository pattern — deliberate omission

The agreed target structure listed a `Repositories/` folder. I am **not** creating
one initially, and the reason is worth stating because it will come up in an
interview:

`DbContext` is already a Unit of Work, and `DbSet<T>` is already a repository.
A `Repository<Incident>` that wraps `DbSet<Incident>` with `GetById`/`Add`/`Update`
adds a layer of indirection, loses `IQueryable` composability (so filtering,
paging and projection get worse or leak back out anyway), and buys an abstraction
over a database we are not going to swap.

Services will use `AppDbContext` directly. A repository or query object gets
introduced **only** when a specific non-trivial query needs to be shared by more
than one service — at which point it earns its place. Recorded here so the
omission reads as a decision rather than an oversight.

---

## 3. Backend project layout

A **single** ASP.NET Core project plus a test project — not a four-project
Domain/Application/Infrastructure/Api split.

Justification: Clean Architecture's project separation pays off when you have
multiple entry points, enforced dependency directions across teams, or a genuine
need to swap infrastructure. This is one API, one database, one developer. Folder
boundaries give us the same organisation; project boundaries would give us
assembly wiring, more `.csproj` churn, and interfaces defined in one project
solely to be implemented in another. If it ever needs splitting, the folder
structure below is already the seam.

```
backend/
├── IncidentPlatform.slnx        ← .NET 10 default: XML solution format, not .sln
├── IncidentPlatform.Api/
│   ├── Controllers/          thin HTTP endpoints
│   ├── Services/             business logic implementations
│   ├── Interfaces/           service contracts (for DI + testing)
│   ├── DTOs/                 request/response contracts, grouped by feature
│   ├── Models/               EF Core entities + domain enums
│   ├── Data/                 AppDbContext, entity configurations, seed data
│   ├── Middleware/           exception handling, request logging, audit capture
│   ├── Exceptions/           typed app exceptions (NotFound, Forbidden, Conflict…)
│   ├── Validators/           FluentValidation validators
│   ├── Authentication/       JWT issuing, password hashing, token service
│   ├── Authorization/        policies, requirements, handlers, role constants
│   ├── Configuration/        strongly-typed options (Jwt, Storage, Cors…)
│   ├── Mapping/              entity ↔ DTO mapping
│   └── Program.cs            composition root
└── IncidentPlatform.Tests/   unit + integration tests
```

`Data/` holds one `IEntityTypeConfiguration<T>` per entity rather than a giant
`OnModelCreating`. Seventeen tables in one method is unreadable and merge-hostile.

---

## 4. Middleware pipeline order

Implemented pipeline (2026-09-24):

1. Security headers (registered on response start, including error responses).
2. Request logging and outer exception handler.
3. HTTPS redirection and HSTS outside Development.
4. Routing and CORS.
5. JWT authentication, with active-user/current-role verification against MySQL.
6. Audit failure capture, surrounding an inner exception handler.
7. Bounded login-identity extraction (16 KiB, rewound for MVC).
8. Built-in partitioned rate limiter, then authorization and controllers.

Authentication precedes user-based limiting so partitions use a validated user ID,
as required by the [ASP.NET Core rate limiter guidance](https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit-samples?view=aspnetcore-10.0).
Anonymous login limiting still precedes password hashing and controller work.
Socket IP is used unless trusted proxy forwarding is explicitly configured later.

Mutation auditing wraps SaveChangesAsync in a transaction (or savepoint inside an
existing transaction), saving generated entity IDs without allowing unaudited data
to commit. A request-local IAuditContext carries identity and transport metadata;
services do not depend on HTTP types. Failure auditing uses a fresh context after
exception translation so failed service state cannot leak into the database.

Readiness uses a tagged database health check, while liveness excludes dependencies.
The MySQL provider uses an explicit MySQL 8 server version, avoiding a connection
just to resolve DbContext options. Startup seeding still requires MySQL.

---

## 5. Cross-cutting decisions

| Concern | Decision | Why |
|---|---|---|
| Errors | Global handler → RFC 7807 `ProblemDetails` | One error shape for the client; stack traces never leave the server in Production |
| Validation | FluentValidation on request DTOs | Rules stay out of entities and controllers; complex conditional rules stay readable |
| Logging | Serilog, structured, correlation id per request | Text logs can't be queried; structured events can |
| Config | Strongly-typed `IOptions<T>`, validated at startup | A missing JWT secret should crash on boot, not on first login |
| Secrets | .NET User Secrets locally, environment variables in deployment | Never in `appsettings.json`, never in Git |
| Enum storage | Persisted as **strings** via `HasConversion<string>()` | A raw `3` in the DB is unreadable, and inserting an enum member later silently shifts every stored value. Costs a few bytes; worth it |
| Time | UTC everywhere, `DateTime.UtcNow` via injectable clock | Incident timelines are forensic evidence; ambiguous local time ruins them. Injectable so tests can control it |
| Concurrency | Optimistic concurrency token on `Incident` | Two analysts editing one incident must not silently overwrite each other |
| API state | Stateless — no server session, no sticky sessions | Required for horizontal scaling behind a load balancer later |

---

## 6. Frontend architecture

Angular 22.1, standalone components (no `NgModule`), signals for local state.

Scaffolding decisions, all deliberate:

| Choice | Value | Reason |
|---|---|---|
| SSR / prerendering | **Off** | Every page sits behind a login. There is no SEO benefit, and server-rendering an authenticated dashboard means handling tokens on the server — complexity for nothing |
| Change detection | **Zoneless** (no `zone.js`) | Angular's current direction, and the whole app is `HttpClient` + signals, which need no zone patching. Smaller bundle, no monkey-patched globals |
| Stylesheets | Plain CSS | Per the agreed stack. Modern CSS has nesting and custom properties; a preprocessor is not needed |
| Test runner | Vitest | The CLI's current default, replacing Karma |
| File naming | **2025 style guide** — `app.ts`, `auth.ts`, not `app.component.ts`, `auth.service.ts` | Angular's current official convention, and what `ng generate` produces by default. Note this differs from most pre-v20 tutorials you will find online; the folder gives the context the suffix used to |
| TypeScript | 6.0, `strict` | Strict mode on from the start — retrofitting it later means fixing hundreds of errors at once |

```
frontend/src/app/
├── core/            singletons: guards, interceptors, API services, models
├── shared/          reusable dumb components (tables, badges, pagination)
├── layout/          shell: sidebar, topbar, content outlet
└── features/        one lazy-loaded route bundle per domain area
```

- **Auth interceptor** attaches the JWT; a response interceptor handles 401 by
  clearing session state and redirecting to login.
- **Route guards** are UX only. Stated again because it is the single most
  common misunderstanding in full-stack portfolio projects: removing a guard in
  DevTools must gain the user nothing, because the API refuses independently.
- **Feature modules are lazy-loaded** so an analyst never downloads the admin
  user-management bundle.
- Typed models in `core/models/` mirror the backend DTOs — the API contract in
  `api-design.md` is the single source of truth for both sides.

---

### Implemented frontend slice (2026-09-24)

Login, guarded shell, incident list/detail/create/actions, evidence, user administration,
and dashboard pages now consume the API.
The workspace explicitly enables zoneless change detection and strict templates.
Feature routes are lazy; numeric enum options match the current C# wire format.
Incident and alert lists use server-side pagination, filtering, search and sorting, with all
list state in the URL query string. Alerts use one route (`alertsMatcher`) for the queue and
the selected alert, so the queue component is reused when the triage panel opens.

Access tokens remain in memory. Concurrent route guards share one refresh-cookie
request on reload. API 401 responses clear the session and return to login without
replaying mutations. The interceptor attaches JWTs only to same-origin `/api/`
requests. Logout waits for cookie revocation before clearing local session state.
Route guards are UX controls; the server owns authorization.

Dates from the API are UTC (including unsuffixed MySQL datetime values); forms
convert local datetime input to UTC. Detail renders user text through interpolation.
Incident edits submit the current version. A conflict preserves the draft and requires an
explicit reload; assignment, status and closure use their separate endpoints. Evidence uses
multipart uploads and JWT-authenticated Blob downloads. Destructive actions have inline
confirmation. User administration has an additional Admin guard, with role-aware navigation.

The dashboard aggregates eight API reads, with cancellation when the selected period changes.
Native HTML/CSS charts expose counts and a trend table without a charting dependency. Null
response metrics remain unavailable rather than becoming zero; each metric shows its sample
count. Workspace totals and rankings are all-time, while trend/metrics selectors affect only
their respective requests.

See `frontend/README.md` for proxy setup, production hosting and verification.

## 7. What is deliberately deferred

Adding these before the MVP works would be premature:

| Deferred | Until | Reason |
|---|---|---|
| Redis | after MVP | Nothing to cache until real query costs are measured |
| Docker | Phase 28 | MySQL 8 already runs locally; containers add a moving part now |
| Multi-tenancy | if ever needed | Retrofitting `TenantId` is real work, but building it unused is worse. The seam: every query already goes through a service layer |
| SIEM/EDR ingestion | post-MVP | The `Alerts` table models an ingestion target; connectors come later |
| Kubernetes | no current plan | Not justified at this scale |
| Permission-level RBAC | post-MVP | Three roles do not need a permission matrix yet; the `Roles` table leaves room |

---

## 8. Related documents

- `database-design.md` — ERD, all 17 tables, keys, indexes, design decisions
- `api-design.md` — endpoint contracts, paging/filtering/sorting conventions
- `security.md` — authn/authz model, threat-by-threat controls
