# Architecture

> **Status:** DESIGN — agreed 2026-08-22. Nothing in this document is implemented yet.
> Each section is marked ✅ implemented / 🚧 in progress / 📋 planned as the build proceeds.
> This file must be updated whenever the real architecture diverges from it.

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
├── IncidentPlatform.sln
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

Order is behaviour, not preference. A misordered pipeline produces real security
bugs — e.g. rate limiting placed after authentication lets unauthenticated
attackers exhaust CPU on token validation.

```
1. Global exception handler      catch everything below it → ProblemDetails
2. Request/correlation logging   assign correlation id, log method/path/status/duration
3. HTTPS redirection + HSTS
4. Security headers              CSP, X-Content-Type-Options, Referrer-Policy…
5. CORS                          must precede auth so preflight isn't rejected
6. Rate limiting                 cheap rejection before expensive work
7. Authentication                who are you? (validate JWT, populate principal)
8. Authorization                 may you? (policies, roles)
9. Audit capture                 record the authenticated, authorized action
10. Controllers
```

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

Angular 22, standalone components (no `NgModule`), signals for local state.

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
