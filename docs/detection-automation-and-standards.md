# Detection automation and standards coverage

Baseline date: 2026-09-26. Scope: this university Windows 11 lab, its API host, four native Windows detection rules and incident triage. No organization-wide certification or compliance score is asserted.

## Implemented behavior

`/automation` is visible to Admin and Security Manager. Only Admin may change policies. Modes: Disabled (automation off, detection continues), Observe (record a decision, keep alert New), AutoPromote (open/link an investigation). Policies begin in Observe. AutoPromote is supported for Defender event 1116 and Security event 1102. Events 4720/4732 require human review and the API rejects automatic promotion for them.

An administrator chooses an active SOC owner and a correlation window of 5-1440 minutes. Each save increments the version and records an immutable audit entry. New policy versions apply only to alerts received after that save. Existing observed alerts remain for manual triage, not replayed. Decision snapshots retain the policy, approver, source reference, catalog version, event ID and fingerprint. Original event XML also remains in the alert payload independently of raw event retention.

The worker checks every five seconds, handling up to 50 candidates per cycle. It only trusts alerts linked to collector-owned event rows matching the expected channel, provider and ID. An API-supplied alert payload alone is insufficient. A policy lock serializes correlation; an alert row lock coordinates with manual promotion and false-positive triage. A unique decision index prevents replay. Incident creation/linking, timeline, alert status, decision and audit commit in one transaction. The system actor is explicit in audit and timeline. Incident CreatedBy records the policy-approving administrator, not a claim of manual creation. Disabled/inactive approvers or owners yield NeedsReview without creating an incident.

Correlation is deliberately narrow: same host, rule, policy version and a still-open incident created inside the configured fixed window. Resolved/closed/false-positive incidents are not reused. Two distinct Defender detections on one host may be grouped; investigators must review all linked evidence. Severity and priority are High, with category Malware for Defender and Other for audit clearing. No endpoint isolation, malware execution, automatic remediation or AI decision authority is included.

## Rule provenance

These are original local rules based on Microsoft documentation, not imported Sigma content. Catalog revision `2026-09-26.1`. Channel and provider are required in addition to Event ID.

| Rule | Event | Primary source | Review caveat |
| --- | --- | --- | --- |
| WIN-DEFENDER-DETECTION | 1116 | https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus | Includes potentially unwanted software; investigate remediation and context |
| WIN-AUDIT-CLEARED | 1102 | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 | Authorized maintenance is possible |
| WIN-ACCOUNT-CREATED | 4720 | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720 | Routine provisioning is common |
| WIN-LOCAL-GROUP-MEMBER | 4732 | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 | Group need not be privileged |

## Framework crosswalk (engineering interpretation)

| Framework / version | Link | Current technical contribution | Remaining evidence |
| --- | --- | --- | --- |
| NIST CSF 2.0 DE.AE-08 | https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20 | Explicit criteria for declaring an incident and recorded decisions | Organization-approved incident criteria, scope and periodic evaluation |
| CIS Controls v8.1 8.2 / 8.9 / 8.11 | https://cas.docs.cisecurity.org/en/latest/source/Controls8/ | Local collection, centralized storage and traceable analysis | Enterprise coverage, source completeness and documented recurring human reviews |
| CIS Controls v8.1 8.10 | Same CIS reference | Retention duration is visible | Current default 7 days does not meet minimum 90 days; size storage, configure retention and verify actual retention history |
| ISO/IEC 27001:2022 | https://www.iso.org/standard/27001 | Technical monitoring/incident evidence that can support an ISMS | Licensed Annex A review, risk assessment, Statement of Applicability, governance and independent assessment; no clause-level conformity asserted |
| CIS Windows Desktop Benchmark | https://www.cisecurity.org/benchmark/microsoft_windows_desktop | Windows 11 scope recorded; Level 1 proposed | Official edition/version/profile not pinned, no configuration assessment executed; status Not assessed |

Registry discovery reports Professional edition, display version 23H2, build 22631. The legacy ProductName value says Windows 10 Pro; do not use that string alone to select the benchmark. The user confirms Windows 11. Event detection cannot substitute for checking Windows configuration against a versioned Benchmark. No hardening settings, firewall policies, auditing configuration or permissions are changed by this feature.

## Validation and operating procedure

Automated tests use only the `_tests` database. They validate concurrent replay, correlation, closed incidents, observation mode, untrusted/mismatched evidence and protected policy APIs. Browser fixtures are not application data.

Start with Observe, review legitimate and suspicious lab activity, ensure required channels are readable, then select a responsible owner and save AutoPromote for the selected supported rule. No fake alerts are inserted to make the dashboard look active. Review NeedsReview outcomes and worker errors. A worker restart retries uncommitted decisions; committed decisions remain deduplicated.

## Remaining work

Pin the applicable official CIS Windows 11 benchmark and implement/test its configuration checks; supply licensed ISO control text for exact clause crosswalk; add reviewed Sigma imports only after implementing supported semantics and preserving license/provenance; define enterprise retention, source inventory and review evidence. These are tracked gaps, not completed compliance claims.
