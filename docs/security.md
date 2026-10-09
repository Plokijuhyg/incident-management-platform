# Security Design

> **Status:** DESIGN — agreed 2026-08-22. Nothing here is implemented yet.
> Controls are marked ✅ implemented / 🚧 partial / 📋 planned as the build
> proceeds. **A control marked ✅ must be verifiable by a test or a manual check
> recorded in this file.** No control is ever marked done on intent alone.

---

## 1. The core principle

> **The Angular application is not a security boundary. The API is.**

The SPA is downloaded to a machine the attacker controls. Its source is readable,
its route guards are removable in DevTools, its `*ngIf="isAdmin"` is a CSS-level
suggestion. Every guard and conditional render in the frontend exists for **user
experience** — not showing people doors they cannot open.

The consequence, applied without exception: every request is authorized on the
server from the token's claims and the database's state, and **nothing the client
asserts about identity, role, or ownership is believed.** A user id in a request
body is ignored in favour of the one in the validated JWT.

This is the single most common failure in full-stack portfolio projects and the
thing an interviewer will probe first.

---

## 2. Authentication

### Password storage

ASP.NET Core Identity's `PasswordHasher<T>` — **PBKDF2-HMAC-SHA256, 600,000
iterations, 128-bit random per-password salt**, in Identity's versioned format.

- Salted per-password, so identical passwords produce different hashes and one
  rainbow table cannot attack the set.
- Deliberately slow, so offline cracking of a stolen database is expensive.
- Versioned format, so the work factor can be raised later and hashes upgraded
  transparently on next login.
- Never MD5, SHA-1, SHA-256, or any unsalted fast hash. Those are checksums for
  data integrity; using one for passwords means a leaked table is cracked in hours.

Passwords are never logged, never returned by any endpoint, never included in
audit `Details`, and never sent by email.

### JWT

| Setting | Value | Reason |
|---|---|---|
| Algorithm | HMAC-SHA256 | Symmetric is correct for a single-issuer/single-audience API |
| Access token lifetime | **15 minutes** | A stolen token has a short blast radius |
| Refresh token lifetime | 7 days, rotating, one-time-use | Reuse of a rotated token means theft → revoke the family |
| Signing key | ≥ 32 random bytes, from configuration | Never in `appsettings.json`, never in Git |
| Validation | issuer, audience, lifetime, **and signature** — all on | `ValidateIssuerSigningKey = false` would accept forged tokens |
| Clock skew | 30 s (not the 5-minute default) | The default silently extends every token's life |

Claims carried: `sub` (user id), `email`, `role` (one per role), `jti`. **No
sensitive data and no authorization *decisions*** — a JWT is base64, not
encrypted; anyone holding it can read the payload.

Refresh tokens live in an **HttpOnly, Secure, SameSite=Strict cookie**, so XSS
cannot exfiltrate them. The short-lived access token is held in memory by the
Angular app — deliberately **not** `localStorage`, which any injected script can
read.

### Account protection

Failed-attempt counter with lockout after 5 failures (`Users.FailedLoginAttempts`,
`LockedOutUntil`), plus the `login` rate-limit policy. Login failures return one
generic 401 for every cause — unknown email, wrong password, locked, deactivated.
Distinguishing them hands an attacker a valid-account oracle.

Deactivating a user (`IsActive = false`) blocks new logins immediately; existing
access tokens remain valid until they expire, which is the accepted cost of
stateless auth. Refresh is refused, so the maximum exposure is 15 minutes.

---

## 3. Authorization (RBAC)

Three roles, enforced by ASP.NET Core policies. Role names are constants in
`Authorization/Roles.cs` — never string literals scattered through controllers,
because a typo in `[Authorize(Roles = "ADMlN")]` fails open in the worst way.

| Capability | Analyst | Manager | Admin |
|---|---|---|---|
| View incidents / alerts / IOCs / assets / MITRE | ✔ | ✔ | ✔ |
| Create incidents, alerts, IOCs | ✔ | ✔ | ✔ |
| Edit incident **assigned to them** | ✔ | ✔ | ✔ |
| Edit **any** incident | ✖ | ✔ | ✔ |
| Assign / reassign incidents | ✖ | ✔ | ✔ |
| Close incidents | ✖ | ✔ | ✔ |
| Override priority | ✖ | ✔ | ✔ |
| Create / edit assets | ✖ | ✔ | ✔ |
| Delete evidence | ✖ | ✔ | ✔ |
| Manage users & roles | ✖ | ✖ | ✔ |
| Read audit logs | ✖ | entity-scoped | ✔ |

**Two kinds of check, and they are not interchangeable:**

1. **Role checks** — coarse, declarative, on the endpoint: `[Authorize(Policy = ...)]`.
2. **Resource ownership checks** — "is this incident assigned to you?" — cannot be
   expressed as a role and live in the **service layer**, where the entity is
   loaded. Attribute-only authorization is exactly how IDOR bugs happen.

Both must pass. A denied resource check is audited as `DENIED` (see §9) because an
analyst probing incidents they were never assigned is a signal worth alerting on.

---

## 4. OWASP-mapped controls

### A01 Broken Access Control / IDOR

The threat: `GET /api/incidents/42` succeeds for a caller who should not see
incident 42, simply because they changed the number in the URL.

Controls:
- Every single-resource fetch loads the entity **and then** authorizes it against
  the caller. Never "authorize the route, then trust the id".
- Not-permitted resolves to **404, not 403**, where the resource's existence is
  itself sensitive. A 403 confirms "this incident exists but isn't yours", which
  is a working enumeration oracle.
- Nested routes verify the parent chain: `/api/incidents/5/evidence/900` confirms
  evidence 900 actually belongs to incident 5. Otherwise the nesting is decoration
  and any evidence id is reachable through any incident.
- Sequential integer ids are retained (readable, good index locality) — the defence
  is the authorization check, not id obscurity. GUIDs would only make enumeration
  tedious, not impossible, and are not a substitute for a check.

### A03 Injection

- **SQL:** EF Core parameterises everything. No string-concatenated SQL anywhere.
  Where raw SQL is ever unavoidable, `FromSqlInterpolated` with parameters — never
  `FromSqlRaw` with an interpolated string.
- **Sort/filter injection:** `sortBy` is matched against a per-endpoint allow-list
  and mapped to a column in code. Passing a user string into a dynamic `OrderBy`
  is injection with extra steps.
- **JSON payloads:** `RawPayload` and audit `Details` are stored as MySQL `json`
  and treated as untrusted data on the way out — never evaluated, never rendered
  as HTML.

### A03 XSS

The nastiest fit for this application: **incident data is attacker-controlled by
definition.** A phishing subject line, a malicious filename, a URL IOC — the
attacker authors that text and we display it back to analysts. A SOC tool that
XSSes its own analysts is a genuine escalation path.

- Angular escapes interpolated bindings by default. **`innerHTML`, `bypassSecurityTrustHtml`,
  and any `DomSanitizer` bypass are banned in this codebase**; if one is ever
  needed, it requires a comment justifying it and a note in this file.
- IOC values are **defanged for display** (`hxxp://`, `evil[.]com`) so an analyst
  cannot fatally misclick a live malicious URL rendered in our own UI.
- Content-Security-Policy header restricting `script-src` to self, so an injected
  inline script has no path to execute.
- Validation on write (type-appropriate format checks per IOC type), escaping on
  render. Both — sanitising only on input means one missed path is permanent.

### A05 Security Misconfiguration

- Swagger and detailed errors: **non-Production only.**
- Stack traces never in an HTTP response; correlation id instead.
- Security headers on every response: `Content-Security-Policy`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Strict-Transport-Security`,
  `Permissions-Policy`. `X-Powered-By`/`Server` removed — free version
  reconnaissance otherwise.
- **CORS:** an explicit origin allow-list from configuration.
  `AllowAnyOrigin()` + `AllowCredentials()` is never used — that combination is
  invalid and, where browsers tolerate it, catastrophic.
- HTTPS enforced with redirection + HSTS.
- Default admin credentials come from user-secrets/environment, never a literal in
  source, and the seeder refuses to run with an unset password.

### A04 Mass assignment

Never bind an EF entity to a request body. Every write takes a purpose-built DTO
containing **only** the fields that operation may change. `IncidentUpdateRequest`
has no `CreatedById`, no `Status`, no `Version`-bypass — so a crafted body cannot
reassign ownership or forge a lifecycle jump. Milestone timestamps, audit fields,
and `IncidentNumber` are set by the service, never accepted from the client.

### A08 Integrity / A09 Logging failures

Covered by §5 (evidence hashing) and §9 (audit logging).

### A06 Vulnerable dependencies

`dotnet list package --vulnerable --include-transitive` and `npm audit` in CI
(Phase 29); Dependabot on the repository. Builds fail on high-severity advisories
rather than warn — a warning in CI output is a warning nobody reads.

---

## 5. Secure file upload — evidence

The highest-risk feature in the application, and the one most worth explaining.
Evidence files are **submitted during investigations of malicious activity**; some
will legitimately *be* malware samples. Every control assumes hostile input.

| # | Control | Why |
|---|---|---|
| 1 | Size limit (25 MB default, configured) enforced at both Kestrel and endpoint | Unbounded upload = disk exhaustion DoS |
| 2 | Extension allow-list — never a block-list | Block-lists are always incomplete; `.aspx`, `.php7`, `.svg` outlive any list |
| 3 | **Content-type verified from magic bytes**, not the client's `Content-Type` header or the extension | Both are attacker-supplied strings. A `.png` claiming `image/png` can be a script |
| 4 | Filename sanitised; `..`, path separators, control characters, null bytes stripped | Path traversal → arbitrary file write |
| 5 | Stored under a **random GUID name** with a safe extension; original name kept only as a metadata string | Defeats traversal and collisions; the disk name is never attacker-influenced |
| 6 | Stored **outside the web root**, in a directory with no execute permission and no static-file mapping | An uploaded file that can be requested and executed is remote code execution |
| 7 | **SHA-256 computed on the received stream** and stored | Chain of custody: proves the file is unaltered. Also detects duplicates |
| 8 | Download only through an authorized endpoint that re-checks incident access, streaming from disk | Direct URLs would bypass authorization entirely |
| 9 | Download served with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` | Forces save-not-render, so a stored HTML/SVG payload cannot execute in our origin |
| 10 | Upload and download both audited (`EVIDENCE_UPLOADED`, `EVIDENCE_DOWNLOADED`) | Who touched the evidence is itself evidence |
| 11 | Rate limited per user | Prevents storage-filling abuse |
| 12 | Deletion restricted to Manager/Admin and audited | Chain of custody must not be quietly breakable |

Deliberately **not** claimed: no antivirus scanning in the MVP. Real evidence
handling would scan on ingest or store samples in a quarantined bucket. Recorded
as a known gap rather than pretended.

---

## 6. Input validation

FluentValidation on every request DTO — length bounds on all strings, enum
membership (an unknown severity is `400`, never a silent default), UTC range sanity
on dates, `pageSize` capped, required fields genuinely required.

Domain-specific validation per IOC type: IPs parsed as real addresses, hashes
matched to exact expected lengths (MD5 32, SHA-1 40, SHA-256 64 hex chars), emails
and URLs format-checked. This is data-quality *and* security: it is what keeps the
`UNIQUE (Type, Value)` catalog from filling with junk that defeats correlation.

Validation runs **server-side**, always. Angular form validators are UX.

---

## 7. Secrets management

| Secret | Local | Deployed |
|---|---|---|
| MySQL connection string | .NET User Secrets | Environment variable / cloud secret store |
| JWT signing key | .NET User Secrets | Environment variable / cloud secret store |
| Seed admin password | .NET User Secrets | Environment variable |
| Sentry DSN, future API keys | .NET User Secrets | Environment variable |

`appsettings.json` holds **structure and non-secret defaults only** — key names
with empty values, so a missing secret fails loudly at startup rather than falling
back to a committed placeholder. `appsettings.Development.json` is already
gitignored. Startup validates that required secrets are present and non-default;
the app refuses to boot otherwise, because a JWT key silently defaulting to
`"changeme"` in production is the worst possible outcome.

Nothing containing a password, key, token, or connection string is ever committed.

---

## 8. Data isolation — no pretending about RLS

MySQL 8 has **no PostgreSQL-style Row Level Security.** There is no `CREATE POLICY`
and no database-enforced per-row filtering, and this document will not imply
otherwise.

Isolation is enforced in application code:
- Every query that returns a filtered-by-permission set applies its predicate in
  the service layer.
- Analyst-scoped views (`myOpenIncidents`) filter on the JWT's user id — never on
  a client-supplied id.
- Currently, all three roles may *read* all incidents (a SOC is a collaborative
  team; hiding incidents from analysts would be actively harmful). The restrictions
  are on **write** and on **administration**, per §3.

If multi-tenancy is ever needed: add `TenantId` to tenant-owned entities, resolve
it from the token, and enforce it with an EF Core **global query filter** so it
cannot be forgotten in an individual query — plus tests proving cross-tenant reads
fail. Not built now, and not pretended.

---

## 9. Audit logging

Append-only `AuditLogs` (see `database-design.md` §4.12). No update or delete path
exists in the application.

Audited: authentication events including failures and lockouts; every incident
create/update/status/assignment/close; evidence upload, download, delete; IOC and
asset mutations; user and role administration; and **every authorization denial**.

Each entry records actor (id **and** a denormalised email snapshot), action,
entity type + id, outcome (`SUCCESS`/`FAILURE`/`DENIED`), source IP, user agent,
UTC timestamp, and a `Details` JSON of changed fields.

`Details` never contains passwords, tokens, hashes, secrets, or file contents —
an audit log is a high-value target, and stuffing credentials into it turns a
read-only leak into a full compromise.

`DENIED` is separated from `FAILURE` precisely so "who is probing what" is a
one-line query.

---

## 10. Known gaps

Stated plainly, because a security document that claims completeness is not
credible:

| Gap | Status |
|---|---|
| No antivirus scanning of uploaded evidence | Accepted for MVP, §5 |
| No MFA | Post-MVP; a real SOC tool would require it |
| Access tokens survive user deactivation for ≤15 min | Accepted cost of stateless JWT |
| No field-level encryption at rest | Relies on database/disk encryption |
| Status transitions unvalidated until Phase 8 | Deliberate, documented |
| No automated penetration testing | Manual checks + `/security-review` per phase |
| No secret scanning in CI yet | Phase 29 |

---

## 11. Verification plan

Security claims need proof, not prose. Each control gets checked as it lands:

- **Integration tests** for authorization: an analyst calling a manager-only
  endpoint gets 403; a user fetching another's incident gets 404; a request with no
  token gets 401; a tampered token signature gets 401; an expired token gets 401.
- **Upload tests:** oversized file → 413; disallowed extension → 415; a `.png`
  whose magic bytes are HTML → rejected; `../../evil.txt` → sanitised.
- **Concurrency test:** two updates with the same `version` → second gets 409.
- **Manual checks per phase:** confirm no secret in the diff, no stack trace in a
  Production-mode error, headers present on responses.
- `/security-review` run against each phase's diff before commit.

A control's ✅ marker in this file is only earned once its check exists and passes.

## 12. Deferred (TODO) — not yet implemented

These are explicitly deferred to a later phase, recorded here so they are not forgotten:

- **Target-side firewall / WAF hardening on the Metasploitable3 VMs.** During the
  two-laptop demo the attack path is intentionally left open — no host firewall, WAF
  or network-level blocking is applied on the vulnerable VMs. Harden (or isolate
  further) after the demo.
- **Vulnerable-VM network exposure.** The lab uses a dedicated point-to-point link
  between the two laptops (`192.168.50.0/24`); the intentionally-vulnerable VM must
  never be bridged onto a shared campus/home network. Keep it off any network that
  carries other devices.
- **Direct LAN API/MySQL exposure.** The two-laptop setup serves the Angular dev
  server on `0.0.0.0:4200`; the API stays `localhost` (reached via the dev-server
  proxy) and MySQL stays `localhost`. Do not publish the API or MySQL on the LAN.
