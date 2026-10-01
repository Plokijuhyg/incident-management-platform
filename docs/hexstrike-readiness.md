# HexStrike assessment readiness

HexStrike HTTP health on port 8888 is separate from the authenticated private gateway on 9443. A healthy HTTP service does not prove that MCP tools can be enumerated. Lab connections now offers a separate Check assessment gateway button and links to Assessments. Assessments rechecks unavailable discovery every 30 seconds while visible, and clears stale connected status on a failed request.

On 2026-09-28, the Windows host had an 8888 listener but no 9443 tunnel. Start-LabConnections.ps1 restored the missing forward. The gateway then returned its generic discovery failure. Direct checks on Kali confirmed healthy HexStrike 6.0.0, 150 MCP definitions, and successful catalog construction. The generic error did not retain enough detail to prove which discovery stage had failed. After restarting the gateway with stage-specific diagnostics and a 20-second manifest budget (previously 10 seconds), live API discovery succeeded repeatedly. Diagnostics expose the stage and exception type only, never credentials or subprocess output. Execution still revalidates the live manifest and existing allowlist/tiering.

Verified executable presets: Network 8, Web 10, API 3, Cloud 0. These counts distinguish advertised MCP definitions from reviewed, installed, target-scoped presets. Cloud remains unavailable because this lab authorizes a Metasploitable IP, not a cloud account or cluster. No unsupported tool was falsely marked available and no assessment was launched for this repair.

Run scripts/Start-LabConnections.ps1 from the Windows repository when restarting the lab. Keep Kali SSH, HexStrike and the private gateway service running. Check both statuses in Lab connections.
