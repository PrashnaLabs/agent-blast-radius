# OWASP mapping

Primary list: **OWASP Top 10 for Agentic Applications (2026)**, published by the OWASP GenAI
Security Project on 2025-12-09. Titles are as published in its announcement.

| Id | Title | Use it when the finding is about |
|----|-------|----------------------------------|
| ASI01 | Agent Goal Hijack | Untrusted content (D1) that can redirect what the agent does: the start of every toxic path |
| ASI02 | Tool Misuse | A tool used beyond its purpose: arbitrary SQL, a shell, HTTP to a model-chosen URL, an irreversible action with no gate (D4, D5, D6) |
| ASI03 | Identity & Privilege Abuse | Over-scoped or ambient credentials, prod reachable from non-prod, admin database keys, no per-user identity on tool calls (D2, D3, D7) |
| ASI04 | Agentic Supply Chain Vulnerabilities | Unpinned MCP servers or tool packages, code fetched at start, pickle-based index loads, third-party tool descriptions loaded unreviewed (D8) |
| ASI05 | Unexpected Code Execution | Shell, `eval`/`exec`, code interpreters, `allow_code_execution`, `allow_dangerous_code` |
| ASI06 | Memory & Context Poisoning | Untrusted content written to long-term memory, skills, goals or a vector store that later runs load |
| ASI07 | Insecure Inter-Agent Communication | One agent's output trusted as instructions by another, with no authentication or validation |
| ASI08 | Cascading Failures | No turn limit, spend cap, timeout or circuit breaker; retries that repeat side effects |
| ASI09 | Human-Agent Trust Exploitation | Approvals that exist only in the prompt or the UI; approval cards that do not show what will run |
| ASI10 | Rogue Agents | No kill switch, no audit of tool calls, an agent acting outside its stated scope |

Supplementary, for D8 data leaving the enclave: **OWASP Top 10 for LLM Applications (2025), LLM02
Sensitive Information Disclosure**. Use it when prompts, documents or tool output reach a hosted
model or telemetry endpoint.

A toxic path usually carries ASI01 (entry) plus the id of its sink (ASI02, ASI03 or ASI05).
