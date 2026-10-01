# Incident email and response guidance

The existing Incident remains the source of truth. IncidentNotifications is a small delivery ledger keyed by IncidentId; it stores state/attempts, not a second incident or event stream. A separate worker polls every 15 seconds, outside incident creation transactions. SMTP failures cannot roll back an incident.

Notifications are disabled by default. Configure these user-secret keys on the API host, then restart:

- Notifications:Enabled = true (set last, after recipient review)
- Notifications:Smtp:Host
- Notifications:Smtp:Port = 587 (STARTTLS required; implicit TLS port 465 is unsupported)
- Notifications:Smtp:From
- Notifications:Smtp:To:0 (add indexed recipients as needed)
- Notifications:Smtp:Username and Notifications:Smtp:Password if the server requires authentication
- Notifications:AppBaseUrl = the browser-facing application URL, HTTPS except local loopback
- Notifications:MinimumSeverity = High (Low, Medium, High, Critical)
- Notifications:StartAfterUtc = an explicit UTC timestamp, for example the time notifications are enabled

Keep passwords in user secrets/environment configuration, never source control or chat. No SMTP credentials/recipients are presently configured and no real email has been sent. Admins can inspect GET /api/notifications/status for missing key names and delivery counts without seeing secrets.

Only incidents created on/after StartAfterUtc are eligible, including later severity increases to the threshold. Each incident is notified once; further changes after successful delivery do not trigger another email. Content includes title, severity, linked asset names and the incident link, not description/raw XML or credentials. Missing asset links are explicitly reported. Pending deliveries recheck severity/cutoff before sending. Ordinary failures retry with backoff, at most three attempts; error type only is stored. Failed rows remain visible for operator investigation. Delivery is at-least-once: a crash after SMTP acceptance but before database acknowledgement can duplicate a message. Database advisory locking prevents concurrent workers sending the same pending row.

ResponseRecommendations derives text guidance from the original Windows rule ID or published Sigma tags in existing alert evidence. Alert detail exposes recommendedAction; Incident detail exposes guidance from linked alerts. These are labelled suggestions requiring human review. No firewall, command or target operation is invoked. Unrecognized rules have no invented recommendation. No severity or promotion policy is changed.

Any future executable response needs the existing assessment confirmed flag and gateway tier/scope validation pattern, plus actor/time audit, separately implemented and reviewed; this feature grants no execution permission.

## Verification (2026-09-28)

21 notification/guidance and VirusTotal tests passed against the isolated test database with fake SMTP transport. This covers disabled delivery, retry persistence, one successful delivery per incident, incident preservation, tag-based guidance and malformed evidence. Real API status confirms enabled=false, configured=false and no delivery rows. Migration adds only the IncidentNotifications ledger. Actual external SMTP delivery remains unverified until an operator configures a server and recipients. Chromium smoke passes the recommendation label, SMTP missing-configuration view, and separate raw-health/MCP readiness checks.

Frontend unit suite: 43/43 passing. Gateway suite: 22 passing, one environment-dependent test skipped. Production builds pass; the existing assessment CSS size warning remains.
