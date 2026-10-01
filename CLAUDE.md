# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cybersecurity incident management platform (portfolio project): ASP.NET Core Web API on .NET 10 + EF Core (Pomelo, MySQL 8) in `backend/`, Angular 22 SPA in `frontend/`. Also included: Windows event collection with detection rules, Sigma rule import, automation policies, VirusTotal enrichment, email notifications, and a private Kali "HexStrike" assessment gateway with optional Ollama analysis (`integrations/`). Design docs in `docs/` are kept in sync with the code. When the real architecture diverges, update `docs/architecture.md`, `docs/api-design.md` and `docs/database-design.md`.

## Commands

Run these from the repository root unless noted. The development environment is Windows/PowerShell.

```powershell
npm run start:api        # dotnet run --project backend/IncidentPlatform.Api --launch-profile https  (https://localhost:7146)
npm start                # Angular dev server on http://localhost:4200, proxies /api/** to :7146 (frontend/proxy.conf.json)
npm run build            # frontend production build
npm run test:api         # dotnet test backend/IncidentPlatform.Tests
npm run test:ui          # Vitest via ng test, single run

# Single backend test / class
dotnet test backend/IncidentPlatform.Tests --filter "FullyQualifiedName~IncidentsControllerTests"
dotnet test backend/IncidentPlatform.Tests --filter "FullyQualifiedName~IncidentsControllerTests.SomeMethod"

# Single frontend spec (from frontend/)
npx ng test --watch=false --include src/app/core/services/auth.spec.ts

# Browser smoke test (from frontend/): headless Chrome/Edge against the prod build with API fixtures
npm run build; npm run test:browser      # set BROWSER_PATH if the browser is not in a standard location

# EF Core migrations
dotnet ef migrations add <Name> --project backend/IncidentPlatform.Api
dotnet ef database update --project backend/IncidentPlatform.Api

# Python integrations (stdlib unittest)
python -m unittest discover -s integrations/hexstrike -p "test*.py"
python -m unittest discover -s integrations/sigma -p "test*.py"
```

Prettier is configured in `frontend/.prettierrc`. There is no separate lint step.

### Configuration and secrets

Secrets come from .NET User Secrets (`--project backend/IncidentPlatform.Api`), never `appsettings.json`. The required keys are `ConnectionStrings:DefaultConnection` and `Jwt:*`. These are optional: `Admin:Email`/`Admin:Password` (admin seeding), `Integration:HexStrike*`, `HexStrike:*`, `Lab:*`, `VirusTotal:ApiKey`, `Notifications:*`, `Ollama:*`, `WindowsEvents:*`. Options classes use `ValidateOnStart`, so a missing JWT or CORS setting crashes on boot. Startup always runs seeding (`DataSeeder`, `MitreSeedData`), so the API needs a live MySQL.

### Backend tests need MySQL

Integration tests use `TestApiFactory` (`WebApplicationFactory<Program>`, environment `Testing`). It reads the real connection string from user secrets or env vars, appends `_tests` to the database name, runs `Migrate()`, and refuses to run against a database without that suffix. The factory forces HexStrike, VirusTotal, Notifications and Ollama off. Test parallelization is disabled on purpose (`AssemblyInfo.cs`) because Serilog's static bootstrap logger is shared across factory instances.

## Backend architecture

There is a single API project, organized by folder. It deliberately has no Domain/Application/Infrastructure split and **no repository pattern**: services use `AppDbContext` directly (see `docs/architecture.md` §2–3 for the rationale).

- **Layering rules:** Controllers are thin. They take a DTO, call one service method and map to a status, and they never inject a DbContext. Services never touch HTTP types; the caller arrives via `ICurrentUser` and request metadata via `IAuditContext`. Entities never cross the API boundary; use DTOs in `DTOs/<Feature>/` with mapping in `Mapping/`.
- **Errors:** Services throw typed exceptions from `Exceptions/` (`NotFoundException`, `ForbiddenException`, `ConflictException`, `ValidationAppException`, `AuthenticationFailedException`). `GlobalExceptionHandler` turns them into RFC 7807 ProblemDetails. Request validation uses FluentValidation validators in `Validators/`, which are auto-registered and auto-validated.
- **Authorization:** All authorization happens server-side. Roles are the constants in `Models/Role.cs` (`RoleNames.Admin` = `ADMIN`, `SecurityManager`, `SocAnalyst`) and are used as `[Authorize(Roles = ...)]`. Ownership and assignment rules (for example, analysts edit only incidents assigned to them) live in services. On every request, the JWT `OnTokenValidated` handler in `Program.cs` reloads the user from MySQL. It rejects inactive users, rejects tokens whose `pwdv` claim (SHA-256 of the current password hash) is stale, and replaces role claims with the current DB roles.
- **Middleware order matters** (`Program.cs`, documented in `docs/architecture.md` §4): security headers → Serilog request logging → outer exception handler → HTTPS → routing/CORS → authentication → `AuditMiddleware` → inner exception handler → `LoginIdentityMiddleware` → rate limiter (`Configuration/ApiRateLimiting.cs`) → authorization → controllers.
- **Transactional auditing:** `AppDbContext.Audit.cs` overrides `SaveChangesAsync` to write `AuditLogs` in the same transaction (or a savepoint) as the mutation. During a request, synchronous `SaveChanges` throws, so always use `SaveChangesAsync`. Only fields in the explicit `AuditFields` allow-list are written to audit JSON. Add a field there deliberately, and never add free text, payloads, paths or secrets.
- **Persistence conventions:** There is one `IEntityTypeConfiguration<T>` per entity in `Data/`. Enums are stored as strings (`HasConversion<string>()`) but serialized to the client as numbers, and the frontend models mirror the numeric values. All times are UTC. `Incident.Version` is an optimistic concurrency token: updates must submit the current version and get a 409 on conflict. Incident numbers come from `IncidentNumberSequence` (`IncidentNumberGenerator`), which is race-safe.
- **Background workers** (hosted services registered in `Program.cs`): `WindowsEventCollector` reads local Windows event logs with bookmarks and evaluates `WindowsEventRules` and Sigma `DetectionRule`s to raise alerts. `AutomationWorker`/`AutomationProcessor` applies automation policies (Observe vs AutoPromote alert→incident). `IncidentNotificationWorker` sends SMTP notifications. `AssessmentWorker` dispatches queued assessment jobs to the HexStrike gateway over mTLS and a bearer token (`AssessmentGateway`). Outbound HTTP clients disable redirects and proxies. Lab targets must be on the `ApprovedLabTargets` allow-list, and integrations are disabled by default in repo config.
- Health endpoints: `/health` is liveness with no dependencies; `/health/ready` checks MySQL. OpenAPI is mapped outside Production.

## Frontend architecture

Angular 22 with standalone components, zoneless change detection, signals, strict TS and templates, and plain CSS. File naming follows the 2025 style guide (`auth.ts`, not `auth.service.ts`).

- `core/`: services (API clients), the `auth` guard and interceptor, and `models/` that mirror backend DTOs. `features/`: lazy-loaded route areas. `layout/shell.ts`: the app shell. `shared/components/`: reusable presentational components.
- Auth: the access JWT is held **in memory only**. On reload, the session is restored through a single shared refresh request that uses an HttpOnly cookie. The interceptor attaches the JWT only to same-origin `/api/` requests. A 401 clears the session and redirects to login, and mutations are never replayed. Route guards are UX only, because the API enforces every permission.
- Unit tests use Angular's HTTP testing backend, so they need no real API or DB. `frontend/README.md` documents implemented features, deployment and the live-dashboard and Windows-telemetry behavior in detail.

## Other directories

- `integrations/hexstrike/`: Python gateway that runs on Kali (`gateway.py`, scan policy, MCP transport). See its README for the deployment gate. Never enable it or add real targets or credentials in repo config.
- `integrations/sigma/import_rules.py`: offline Sigma importer (pySigma). By default it only validates, and `--apply` imports rules as *disabled* `DetectionRule`s. The source rules are in `seed-rules/`. Setup is described in `docs/sigma-rules.md`.
- `integrations/windows-agent/`, `scripts/`: PowerShell helpers for remote Windows telemetry enrollment, audit-log enablement and lab connections.
