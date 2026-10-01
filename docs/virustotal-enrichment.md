# VirusTotal enrichment

Open an Alert or Incident, expand Threat intelligence with **Load indicators & saved
reports**, select an existing eligible indicator, confirm sharing it, and choose
**Enrich selected indicator**. For incidents, candidates come from linked IOCs and
up to 20 recent linked alert payloads. Alert candidates come from named structured
fields or original XML Data fields. This is not free-text IOC guessing. Up to 50
candidates/results are shown. Private/reserved IPs and recognized internal domain
suffixes are excluded; public-looking internal names cannot always be inferred.
Review any selected URL for sensitive paths or query tokens before confirming.

The server reads `VirusTotal:ApiKey` from configuration/user secrets. It never
returns or logs it. Only GET requests to the fixed VirusTotal v3 report endpoints
are used. No files, event XML or credentials are uploaded; no URL scan submission,
target connection, automatic containment, severity change or incident promotion
occurs. Scanner/telemetry allowlists remain unchanged. IOC reputation lookups are
not network scans and do not grant target approval.

Nullable `Alerts.EnrichmentJson` and `Incidents.EnrichmentJson` store
indicator, malicious/total verdict counts, categories, status and timestamps.
The provider is VirusTotal for this version (identified by the panel/endpoint and
audit); existing RawPayload evidence is untouched. Enrichment is copied during
manual or automatic creation of an incident from an enriched alert. A later
incident lookup can independently refresh its own snapshot.

Endpoints: GET/POST `/api/alerts/{id}/enrichment` and
`/api/incidents/{id}/enrichment`. POST accepts `{type,value,confirmed:true}` and
requires the indicator to already belong to the selected record. Existing SOC
roles can read reports; incident writes enforce the existing assigned-analyst or
Admin/Manager permission. Every successful request persistence records
`IOC_ENRICHMENT_REQUESTED` without the API key, raw XML or IOC text.

Enrichment is an optional separate request after record creation. Provider
failures/timeouts/404/429 become visible report statuses, never a verdict of zero
and never a failure of Alert/Incident creation. Database failures may fail the
optional enrichment request; existing records remain intact.

Cache: successful reports 24 hours, not-found one hour, transient failures one
minute; per-record snapshots survive restarts. A bounded 2,000-item process cache
coalesces repeated indicators across records. A singleton serializes calls and
limits this API process to four lookups per rolling minute and 500 per UTC day,
with a one-minute provider-429 cooldown and ten-second request timeout. In-memory
quota/cache state resets on restart and is not coordinated across API replicas;
VirusTotal remains authoritative for account quotas. No automatic retry loop or
background bulk enrichment is enabled.

Validation: isolated tests cover normalization, private indicators, cache reuse,
quota limits, provider errors, confirmation, record binding and evidence
preservation. Browser smoke checks selecting and confirming a fixture lookup and
rendering verdict counts. A separate real GET for public `example.com` returned
HTTP 200 using the local key; no test Alert/Incident was added to the real database.

Official API references: https://docs.virustotal.com/reference/overview,
https://docs.virustotal.com/reference/ip-object,
https://docs.virustotal.com/reference/url.
Notifications and recommended response actions are separate pending capabilities.
