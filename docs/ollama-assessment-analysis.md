# Local Ollama assessment analysis

Flow: saved HexStrike assessment observations -> authenticated API -> configured private Ollama server -> five-section defensive brief stored on the same assessment. This is manual review assistance, not an MCP agent and not a tool execution loop.

## Configuration

The verified model is llama3.1:8b. Current lab addresses supplied by the operator are Ollama 192.168.0.100 and app host 192.168.0.105. Configuration lives in API user secrets:

- Lab:OllamaUrl = http://192.168.0.100:11434
- Ollama:Model = llama3.1:8b
- Ollama:Enabled = true

On the Ollama laptop, bind OLLAMA_HOST to its current private address and keep the server running. The inbound firewall rule must permit only the current app host address; DHCP address changes require updating both binding and firewall. OLLAMA_NO_CLOUD=1 keeps the server local. This configuration uses plain HTTP on the private lab LAN, not transport encryption. An authenticated encrypted tunnel/HTTPS endpoint is needed for a network where that boundary is insufficient. No browser CORS change is necessary: only the backend calls Ollama.

## Operator workflow

Open Assessments, inspect a Completed or Partial assessment, then choose Analyze results with Ollama inside the popup. Admin and SecurityManager roles can request analysis. Merely opening a result does not invoke the model. The response is stored in nullable SecurityAssessments.AnalysisJson, added by AddAssessmentAnalysis. Original response, observations, scanner severity and scan status stay unchanged. No Alert or Incident is created or altered by this feature.

The output has five numbered sections: Vulnerability Summary, Attack Surface, Detection Guidance, Mitigation Steps, Severity Justification. The prompt prohibits offensive commands/payloads and requires unknown CVSS, versions or detection specifics to be stated as unknown rather than invented. The model receives no execution tools. Treat its text as unverified guidance and compare evidenceIndex references with original observations.

The server sends up to 40 observations and 16,000 serialized observation characters, with selected field values bounded to 400 characters. Raw tool transcripts, arbitrary JSON fields and credentials from configuration are not sent. Input truncation and total/included observation counts are displayed. A partial scan is explicitly identified. This is not exhaustive analysis of all tool output. An empty result never establishes safety.

A structured JSON response is required from Ollama and converted to the five display sections. Missing sections, model mismatch, tool-call responses and output-limit truncation fail explicitly; no commands are executed. Analysis is plain escaped text in the UI. A completed report is reused for the same evidence fingerprint, input fingerprint, model name and prompt version. A model replaced under the same tag does not currently invalidate this cache automatically.

One analysis at a time per API process, no waiting queue, 180-second timeout, bounded response size and six requests/minute per user. Analysis requests belong to the signed-in browser session. Minimize, Close, backdrop clicks, Escape, and navigation within the app do not cancel generation. A floating status panel restores the assessment and shows completion or failure. Reloading/closing the browser tab, signing out, or losing the connection can still interrupt the request; this is not a durable server job. Completed reports remain saved on the assessment; retry remains manual. Ollama failures are saved as a separate analysis status, never a scan failure. A database failure can prevent saving a report; existing scanner evidence remains intact.

The same HexStrike:Targets approval and target IP are checked before inference and before saving. Target revocation during generation prevents persistence; it cannot retract data already sent. The saved evidence is checked again under a row lock so changed results cannot receive an outdated analysis. Audit events record actor, request/outcome, model and fingerprints, not prompts or model output.

## Endpoints

- GET /api/assessments/analysis/status: configured model and prompt version (configuration readiness, not an inference test).
- POST /api/assessments/{id}/analysis: generate or reuse the saved report; accepts no client-supplied URL, prompt, target or evidence.
- Existing assessment detail GET includes AnalysisJson for reopening saved reports.

Ollama API reference: https://docs.ollama.com/api/chat

## Live verification ? 2026-10-01

The updated API reached Ollama at 192.168.0.100:11434 and generated a complete five-section report for existing assessment 76499635-b34a-4ae0-8f56-cd0cbdc47184 (one normalized observation). Generation took 140.9 seconds on the lab laptop. The persisted report records model llama3.1:8b and prompt version defensive-brief-v2. A second request returned the same GeneratedAt timestamp, reusing the saved report. Scan status, raw response, normalized observations and evidence fingerprint remained unchanged. No new scan or incident was created. Verification summary: logs/ollama-integration-verification.json.

Nine isolated backend tests passed, covering bounded input, restricted endpoints, model/tool-call rejection, connection failure, persistence/cache reuse and approval revocation before/during inference.
