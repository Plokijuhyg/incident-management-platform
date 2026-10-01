# Windows event collection: actual architecture and remote agent

> Current project scope: the user deferred collecting logs from Metasploitable3.
> This agent remains optional and undeployed there; installing .NET/WMF on that VM
> is not required for scanning. Continue local Windows 11 collection independently.
> Assessment work is limited to scanning and reviewing findings; no exploitation workflow is enabled.

## Existing local collection

`Services/WindowsEventCollector.cs` is an API-hosted BackgroundService. It uses
`System.Diagnostics.Eventing.Reader.EventLogSession`, `EventLogConfiguration`,
`EventLogQuery` and `EventLogReader` with the local session. `Environment.MachineName`
is the source. No remote EventLogSession, WMI, WinRM or endpoint agent was present.
Retention cleanup currently belongs to the local collector; remote-only deployments
with that worker disabled need an explicit retention job before extended operation.
The original Windows Security events came from the Windows machine running the API,
not from Kali or Metasploitable. Local collection remains available independently.

## One allowlist, one data model

The implemented scanning allowlist is configuration `HexStrike:Targets`.
`ApprovedLabTargets` was previously a name in the conceptual design, not a database
table. `Services/ApprovedLabTargets.cs` now supplies the existing list to both
scanning and telemetry. No duplicate target registry or Alerts/Incidents schema was
created. Telemetry additionally requires `Hostname` on the approved target, matching
Windows event XML `System/Computer` (short name or FQDN exactly, case-insensitive).

A separate `Telemetry:Agents` list stores credentials bound to target IDs. It does
not grant target approval. Each entry has Id, TargetId, Enabled and TokenSha256.
Changing `Approved` to false rejects the next incoming batch. Disabling an agent
revokes its token. Existing stored evidence is retained. Credentials never grant
access to ordinary user APIs, scanning or incident management.

Flow:

Windows local EventLog API on target -> durable private agent spool -> HTTPS POST
`/api/telemetry/events` -> agent token + shared target approval + socket peer IP +
XML computer validation -> existing `WindowsEvents` -> existing `WindowsEventRules`
-> existing `Alerts` -> existing configured automation/manual promotion -> existing
`Incidents`.

Both local and remote writers call `WindowsEventWriter.Store`, under the same MySQL
collector advisory lock and transaction. A SHA-256 fingerprint deduplicates retries.
No new database migration, finding store, alert type or incident store is required.
A remote batch does not itself create an incident. Existing automation policy still
controls promotion of eligible rule alerts.

## Security contract

- Endpoint disabled unless `Telemetry:Enabled=true`.
- `X-Agent-Id` and a random per-agent `X-Telemetry-Token`; only SHA-256 stored server-side.
- Resource filter authenticates before MVC deserializes the event batch. `[AllowAnonymous]`
  exempts this endpoint from user JWT authorization, **not** from the telemetry filter.
- Source is the actual TCP peer, never JSON, `X-Forwarded-For` or a claimed hostname.
  It must equal the IP in the same approved scanning target. NAT/HTTP reverse proxies
  are not supported by this initial direct-connection design. Do not allowlist a
  proxy or bypass the peer check to make them work.
- XML Computer must match approved Hostname. EventID/provider/channel/time/record ID
  are parsed from bounded original XML; no client-supplied severity or AlertId accepted.
- DTDs/entities are prohibited. Max 64 events, 64 KiB XML characters per event,
  8 KiB message characters, 2 MiB HTTP body. Whole invalid batch rejected atomically.
- Requests rate-limited by real peer IP to 120/minute. Agent retains pending batches
  on 400/401/403/429/503, TLS failure and connection loss; operator must correct permanent
  errors. It retries on the next channel sweep with a five-second pause between sweeps.
- Denied authentication/source/identity attempts produce `AuditLogs` action
  `TELEMETRY_REJECTED`, Outcome Denied, peer and reason, without logging secrets or XML.
  They do not create ordinary Alerts or Incidents. Rate-limit rejections also audit.
  Middleware-level transport failures/oversized requests may terminate before this filter;
  these are HTTP-server rejections, not accepted telemetry. Audit database failure fails
  the request closed; availability of the database is required to persist an audit row.
- Accepted batches produce `TELEMETRY_BATCH_ACCEPTED` with target, agent, batch ID and
  accepted/duplicate counts. Inspect these in the existing Audit Logs UI.

## Agent behavior and compatibility

`integrations/windows-agent/Start-WindowsEventAgent.ps1` uses Windows PowerShell 5.1
and the Windows .NET EventLog APIs, not WinRM. No inbound listener is opened on the
endpoint. Default channels are Security/System/Application; use `["*"]` to discover
all enabled channels, with permission errors visible per channel. More channels mean
longer sweeps; this is near-real-time polling, not a latency guarantee.

The first read looks back five minutes. State is persisted per channel. The agent
uses a record ID plus timestamp anchor because Windows PowerShell's .NET Framework
EventBookmark does not expose the modern BookmarkXml API. It verifies that anchor
before resuming. Cleared logs or rolled-out anchors pause that channel for operator
review, instead of silently resetting. Pending JSON and cursor are atomically replaced;
a confirmed API acknowledgement is required to advance. A crash after server commit
but before acknowledgement simply replays a deduplicated batch. One process per state
directory, 16-event batches bounded to 1.5 MiB, a 256 MiB spool limit (plus at most one
pending batch), and a 30-second HTTP timeout. Spool exhaustion pauses reads; Windows
log retention can still lose source events during extended downtime. This is not an
unlimited archive or a managed fleet service.

Token file is Windows DPAPI-protected for the agent account. Raw spool files have
account/SYSTEM-only ACLs. StateDirectory must be a dedicated folder. Do not reuse a
shared directory: the agent protects its DACL. Run under an account with Event Log
Readers access and actual permission to Security; local policy may require elevation.
The agent does not change audit policy, enable channels, clear logs, open firewall
ports, or install scheduled tasks/services automatically.

Windows 11 includes Windows PowerShell 5.1. **Metasploitable3's actual Windows and
PowerShell/.NET/TLS compatibility has not been verified.** Do not assume this runs
on its original older PowerShell image. Obtain `$PSVersionTable` and OS details first;
if 5.1/TLS 1.2 are unavailable, deployment remains pending. Do not weaken TLS or open
WinRM to work around an incompatible lab VM.

## Deployment (explicit operator steps; not yet performed on target)

1. Verify the real target IP and its event XML Computer value. Keep the existing
   `HexStrike:Targets` approval; add Hostname there. DHCP changes require re-verification.
2. Configure the API HTTPS listener on a management address reachable by the target.
   The current development launch profile binds localhost only. Provision a server
   certificate whose SAN matches the API hostname/IP and whose chain is trusted by
   the target. Configure Kestrel's HTTPS certificate using secrets, not source control.
   Permit inbound API traffic on the Windows API host only from the approved target
   address. No inbound target firewall/WinRM change is needed. Do not expose MySQL.
   No listener or firewall changes are made by the enrollment script.
3. On the API host, run (replace hostname and endpoint with verified values):

   ```powershell
   .\scripts\New-TelemetryEnrollment.ps1 -TargetId metasploitable3 -ComputerName VERIFIED-COMPUTER -Endpoint https://VERIFIED-SIEM-HOST:7146/api/telemetry/events
   ```

   This refuses unapproved targets, preserves existing user secrets, and creates an
   ACL-protected `logs/telemetry-enrollment-<id>` folder containing scripts/config and
   a one-time plaintext token transfer file. It enables telemetry in development user
   secrets. Do not run enrollment concurrently with another settings writer. Protect
   and privately transfer the token; never paste it into chat or commit it. Existing
   tokens are not revoked by creating another enrollment; disable old agents explicitly.
4. On the verified compatible target, copy scripts/config into a dedicated folder.
   Under the SAME account that will run the agent:

   ```powershell
   .\Save-AgentToken.ps1 -TokenFile C:\ProgramData\IncidentPlatformAgent\token.dpapi
   .\Start-WindowsEventAgent.ps1 -ConfigPath .\agent.json -Once
   .\Start-WindowsEventAgent.ps1 -ConfigPath .\agent.json
   ```

   Enter the transferred token at the hidden prompt. Securely remove transfer copies
   after successful enrollment. HTTPS chain and hostname validation must succeed;
   there is no `SkipCertificateCheck` option. `Ctrl+C` stops the foreground agent.
5. Start/restart the API with the configured HTTPS listener, then check Audit Logs for
   accepted batches and Windows Events for the target's Machine. Inspect collector
   warnings on the target. The existing local `/windows-events/status` channel list
   describes the API host collector, not remote agent heartbeats. Fleet heartbeat and
   remote health UI are not implemented in this minimal version.

## Verification performed

Isolated MySQL test database: valid agent creates one original WindowsEvent and one
original rule Alert; replay deduplicates; invalid token, different peer even with a
spoofed forwarded header, forged XML Computer, hostile XML, target revocation and
agent disabling are rejected; no Incidents created. Local Windows smoke test reads a
real System event and retries against a closed loopback port, preserving the same
pending batch and leaving the acknowledged cursor unchanged. No test events are sent
to the real application database. Target-to-API TLS deployment remains unverified.
