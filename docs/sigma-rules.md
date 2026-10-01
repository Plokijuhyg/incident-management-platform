# Sigma definitions in the existing Windows detection pipeline

## Storage and import

`DetectionRules` is the definition store. `AutomationRules` retains its original
incident-policy purpose. The additive migration does not alter Alerts or Incidents.
All existing four built-in Windows detections remain in `WindowsEventRules`.

Use Python 3.12 and `integrations/sigma/requirements.txt`. Official pySigma 1.5.1
parses selectors, boolean expressions, wildcard selector names, modifiers and
condition trees. Our offline adapter serializes that typed tree to JSON. The API
does not parse YAML or call a Python process while handling telemetry.

```
py -3.12 -m venv integrations/sigma/.venv312
integrations/sigma/.venv312/Scripts/python.exe -m pip install -r integrations/sigma/requirements.txt
integrations/sigma/.venv312/Scripts/python.exe integrations/sigma/import_rules.py
```

The default is validation only. To apply, supply `SIGMA_DB_JSON` privately as JSON
with host, port, user, password and database keys (and appropriate PyMySQL TLS
options for a remote database), then append `--apply`. Do not put passwords in
command history or commit credentials. Schema migrations are a separate EF step.
The importer never creates or changes tables. The report is written to
`logs/sigma-import-report.json` and contains no credentials or event evidence.

Import is transactional and serialized by a MySQL advisory lock. External UUIDs
have a unique index. Duplicate IDs in the input, malformed YAML, unknown levels,
and invalid required metadata abort preparation before database writes. A parse or
conversion failure is stored as Unsupported with its reason and original condition
block. Re-import updates matching definitions, preserves CreatedAt, and resets
Enabled=false, so changed logic always requires another review. It does not delete
rules absent from the folder. Every imported row is disabled, including on re-run.

Severity mapping approved by the operator: informational -> Informational,
low -> Low, medium -> Medium, high -> High, critical -> Critical. This is alert
review priority, not proof of compromise or an automatic incident promotion rule.
The first published tag is stored verbatim; it can be a tactic rather than a
technique. All tags, source-relative path, SHA-256, compiler version, original
logsource/detection and false-positive context are retained in DefinitionJson.

## Evaluation and review

Automation & coverage -> Imported Sigma rules -> Load rules provides search,
pagination, source conditions, false positives, disabled state and compatibility
reasons. Admins can enable one reviewed definition at a time; security managers
can inspect. Review uses the definition timestamp for stale-edit detection and
writes DETECTION_RULE_REVIEWED to AuditLogs. No rule is enabled by installation.

The existing WindowsEventWriter receives events only after the existing local
collector or telemetry authentication/allowlist/XML validation. It evaluates
reviewed imported conditions alongside WindowsEventRules and writes normal Alerts.
No new intake endpoint, target registry, alert store or incident store exists.
A match is deduplicated by rule UUID plus event fingerprint. Multiple rules may
match an event; the legacy WindowsEvent.AlertId retains the first alert, while all
alerts preserve the source fingerprint and original XML in RawPayload. Replays
of already ingested events do not run detection again. Enabling a rule applies to
newly ingested events only. An administrator can explicitly re-evaluate 1-100
existing event IDs with `POST /api/detection-rules/{id}/reevaluate`, body
`{ "eventIds": [123], "updatedAt": "<current rule timestamp>", "confirmed": true }`.
The rule must already be enabled and supported. The endpoint uses the same collector
lock, evaluator, alert factory and rule/event deduplication key. It accepts no event
XML or source claims. Missing events, stale rule versions and absent confirmation
are rejected. The original event/time are preserved; alert metadata records
`HistoricalReview`, the administrator and evaluation time. The alert receive time
is the current evaluation time so the reviewed existing incident policy can process
it. Repeating the request returns the existing alert and creates no duplicates.
The audit action is `SIGMA_HISTORY_EVALUATED`. This is an explicit bounded review,
not an automatic backfill or a second rule engine.

Promote a Sigma alert using the existing manual alert-to-incident action. Its
published technique tags are copied into existing IncidentMitreTechniques only
when the technique already exists in the reference catalog, with notes explicitly
identifying these as documentation references, not confirmed attribution. Missing
catalog techniques remain in the alert snapshot. Existing automation policies
govern both built-in and explicitly reviewed imported rules. In Automation, expand an
imported rule, preview up to 1,000 latest stored events, review its conditions, then
choose alerts-only (Observe) or alert-and-incident (AutoPromote). AutoPromote requires
an active incident owner and an administrator's explicit review confirmation.
The existing worker revalidates the stored event fingerprint and condition before
promotion and groups the same rule/host/policy version within the chosen window.
Severity uses the imported rule's existing severity; Informational maps to Low for
incidents because the existing incident enum has no Informational value. This is
incident grouping, not implementation of Sigma temporal correlation rules. No real alerts/incidents are created by import.

## Exact support boundary

This is not a claim of universal Sigma compatibility. Official pySigma parsing
success is distinct from runtime support and from having the required source data.
Supported typed conditions: AND/OR/NOT, selector expansions handled by pySigma,
string equality/wildcards/case-sensitive strings, transformations represented as
strings (including contains/startswith/endswith/base64), regex with i/m/s flags,
numeric comparisons, boolean values, null/existence, CIDR, field references and
value expansions. Regex uses .NET semantics and a 50 ms timeout. Invalid .NET
expressions block enabling; a runtime timeout audits SIGMA_EVALUATION_FAILED and
does not turn an error into a match. Not every Python/PCRE regex dialect is
semantically identical to .NET. Unresolved placeholders, backend query expressions,
unbound keyword searches, timestamp-part values and correlation/aggregation rules are unsupported; their
conversion error remains visible and they cannot be enabled. No correlation rules
were present in the supplied 2,607-file folder.

Source mappings cover Windows Security, System, Application, Defender, PowerShell
and selected Sysmon event categories. Generic process_creation maps to Sysmon 1,
not Security 4688: their fields are not interchangeable. No Sysmon installation,
audit-policy change, channel enabling or remote collection is performed. Cloud,
proxy and other non-Windows sources have no intake mapping and cannot be enabled.
Category availability does not establish channel health or field coverage.
PowerShell fragment reassembly and cross-event correlation are not implemented.

The evaluator must be extended and tested for an unsupported construct before a
rule using it can run. It never falls back to executing arbitrary queries, shell
commands, or interpreting a failed conversion as a successful detector.
