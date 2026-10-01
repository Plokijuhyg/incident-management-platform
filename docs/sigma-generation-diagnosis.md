# Sigma generation and MITRE route verification ? 2026-09-28

## Findings before changes

1. The actual imported rules table is `DetectionRules`; `WindowsEventRules` is a
   class. Direct SQL returned 2,607 definitions, **0 enabled**, no `SIGMA-*`
   automation policies, 59,959 events, zero alerts and zero incidents.
2. The collector was running and event count increased to 60,271. Evaluation is
   per newly ingested event in `WindowsEventWriter.Store`, not a historical sweep.
   Duplicate event fingerprints are skipped. Collector and automation heartbeats
   were current with no general errors. No Sigma evaluation-failure audit rows
   existed. Security channel reads separately reported Access denied.
3. Fields are extracted from original Windows XML and normalized metadata; source
   channels are checked separately. A read-only trace of 224 Security/System/Defender
   definitions against 16,427 existing records found two matching definitions.
   There was no field-mapping failure for either verification rule.
4. Rule 426 (User Logoff Event) matched 16 records, including 36539. Rule 513
   (Windows Defender Malware Detection History Deletion) matched record 17836.
   These are informational patterns, not proof of compromise. Before this task
   neither rule was enabled; no enabled rules existed to trace.
5. Promotion had no input alerts or imported policies. The existing worker was
   running. Isolated tests confirmed policy ownership and incident grouping.

Root cause: missing persisted activation, combined with the expectation that
activation would evaluate already-stored events. Existing ingestion intentionally
has no automatic historical sweep. No schema rewrite or rule-condition weakening
was required.

## Minimal fix and actual verification

Added explicit, admin-confirmed, version-checked historical review of 1?100 existing
event IDs. It shares the collector database lock, Sigma evaluator, alert factory,
rule/event deduplication and existing incident automation. It accepts no external
XML. Original event timestamps remain unchanged; generated alerts include
HistoricalReview metadata and the original receipt time. An audit records who
requested the evaluation. Disabled rules, missing events, stale versions and
absent confirmation are rejected. This is not a new ingestion path.

Only rules **426 and 513** were enabled. Rule 426 uses Observe; rule 513 uses
AutoPromote with owner 709 (Jawad), a 60-minute grouping window, and the existing
Informational-to-Low incident severity mapping.

| Rule | Real event row | Alert | Outcome |
|---|---:|---:|---|
| 426 | 36539 | 82 | Observed, no incident |
| 513 | 17836 | 83 | Promoted to incident 292, INC-2026-000275, Low |

Both requests were repeated: zero additional alerts, one duplicate each.
The automation worker, not a manual incident insert, created incident 292.
These historical signals require analyst review; they do not establish infection.
Evidence summaries: `logs/sigma-real-verification.json` and
`logs/sigma-real-result-rows.json` (local ignored operational evidence).

## MITRE routes

Updated list/detail navigation, incident investigation links, Resources links,
dynamic catalogue links/back navigation, route definitions, and browser assertions
to `/attack-matrix` and `/attack-matrix/:id`. Full frontend search leaves only
valid `/api/mitre/...` backend endpoints; changing those would break the API.
Search output: `logs/mitre-route-audit.txt`.

Validation: 9 Sigma regression tests passed (including historical review rejection,
idempotence and promotion); frontend production build passed with the existing
assessment CSS budget warning; the complete Chromium browser smoke test passed,
including MITRE list/detail navigation. No VirusTotal, notification, recommended
response-action, or database schema changes were made in this task.
