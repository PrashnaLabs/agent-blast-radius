# agent-blast-radius: design spec

**Date:** 2026-11-11 · **Status:** approved, v0.2.0 implemented

## 1. One sentence

An open-source agent skill that checks an AI agent for vulnerabilities before it goes into an
air-gapped or isolated environment. It finds everything that crosses the boundary, and what an
attacker could do through the agent inside it.

## 2. Why

- **An air gap is not a safety property of the agent.** It removes the network path out. It does
  not bound what the agent can do to systems inside the enclave.
- **Agents cross boundaries by default.** Hosted model clients send the whole context out,
  several frameworks export traces or telemetry unless told not to, and MCP servers, packages and
  models are commonly fetched at start or on first use.
- **Documented agent failures are inside-the-boundary failures.** They include an agent deleting a
  production database and its backups with one call using a token it found, agents leaking private
  data after reading poisoned tickets or issues, an infra destroy delegated to an agent, and an
  internal agent used to move from one compromised laptop to other machines. None needed the
  internet. All needed more reach than the task.

Organisations behind these failures are not named anywhere in this project.

## 3. Users and success

- **User:** developers building agents for regulated, on-prem, sovereign or air-gapped
  deployments, who run the skill inside their own coding agent.
- **Success:** one run gives a report with two verdict lines (Boundary, Blast radius). Every
  finding has `file:line` evidence, a failure pattern (or "no known pattern"), an OWASP id and a
  concrete fix. What cannot be seen statically is listed, never assumed.
- **Trust goal:** read-only, fully offline scanner; no secret values printed; neutral, with no product or
  vendor marketing.

## 4. Landscape (checked 2026-11-11)

| Kind of tool | What it does | Gap we fill |
|--------------|--------------|-------------|
| Static agent-graph scanners | Map agents to tools and tag risks | Do not judge credential scope, irreversibility or boundary crossings; some are unmaintained |
| Runtime model probers | Send adversarial prompts to a live model | Never read code; complement, not competitor |
| Readiness-grader skills | Grade eval, tracing and governance | No damage lens, no boundary lens |

Position: **the pre-deployment check for agents going into isolated environments.**

## 5. Scope

**In v0.2**
- Static, read-only audit of a repo containing one or more agents.
- Python and TypeScript, plus Dockerfiles and shell start scripts.
- Frameworks: LangChain/LangGraph, deepagents, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Vercel
  AI SDK, raw tool loops, and MCP client configs.
- D8 boundary crossings plus D1–D7 blast radius, plus a secondary detect-and-recover section.

**Out (each needs real users asking first)**
- Auto-fix. Findings are structured so fixes can plug in later.
- Runtime testing or network-policy verification.
- SARIF/CI mode.

## 6. The model

| # | Dimension | Question |
|---|-----------|----------|
| D8 | Boundary | What needs or reaches outside the enclave: hosted model, telemetry, code or files fetched at start, SaaS connectors, external hosts? |
| D1 | Untrusted input | What attacker-controllable text reaches the context (inside an enclave: imported documents, tickets, shared drives, other agents)? |
| D2 | Reach | What systems, data and credentials can the agent touch? |
| D3 | Privilege fit | Is each credential scoped to the task? |
| D4 | Irreversibility | Which reachable actions cannot be undone? |
| D5 | Egress | Where can data go? |
| D6 | Gates | What stands between intent and action, enforced in code? Prompt-only approvals do not count. |
| D7 | Identity & audit | Can you prove who did what and stop it? |

A **toxic path** is `untrusted source → agent → tool with reach → irreversible action or egress`
with no enforced gate on the way. The lethal trifecta (private data + untrusted content + a way
out) is always Critical.

**Verdicts:**
- Blast radius: CRITICAL, EXPOSED or CONTAINED.
- Boundary: SEALED (nothing crosses), BRITTLE (nothing leaks, but code or files are fetched at
  start) or LEAKY (context leaves by default).

## 7. Architecture

```
agent-blast-radius/
├── README.md, LICENSE (Apache-2.0)
├── skills/agent-blast-radius/
│   ├── SKILL.md                  workflow + report contract
│   ├── references/
│   │   ├── rubric.md             D1–D8 states, severities, verdicts
│   │   ├── patterns.md           anonymous failure patterns P01–P11
│   │   ├── owasp-asi.md          ASI01–ASI10 (+ LLM02 for D8)
│   │   └── frameworks.md         where reach, gates and boundary switches live
│   └── scripts/inventory.py      deterministic, stdlib-only, offline scanner
├── examples/vulnerable-agent/    planted fixture + expected.md golden set
├── examples/sample-report.md
└── tests/test_inventory.py
```

The scanner emits JSON hits by category with `file:line`, MCP entries (`pinned`,
`fetches_at_runtime`), and an `external_hosts` summary. It runs `runtime_fetch` rules only on
Dockerfile CMD and ENTRYPOINT lines, never on RUN. The skill turns these pointers into
findings by reading the code.

**Safety contract:**
- Read-only. Never runs target code, never prints secret values.
- The only write is `BLAST_RADIUS.md`, and the skill asks before overwriting it.

## 8. Pattern catalog rules

- Describe each mechanism without naming the organisation. Record the year, a basis label
  (researcher disclosure, first-person postmortem, press report, default behaviour), the shape and
  a "Matches when" line.
- Keep sources in private notes, not in the repo.
- A finding cites a pattern only when the mechanism matches.

## 9. Testing

- Scanner: exact hit set against the fixture, the build-time versus runtime install rule, the external hosts
  summary, MCP fields, secret redaction, vendor-dir skipping, the per-rule cap, determinism.
- Skill: `examples/vulnerable-agent/expected.md`, checked by hand before each release, ideally by a
  fresh agent session.

## 10. Decisions

1. Name `agent-blast-radius`.
2. Audit only; no code changes to the target.
3. Scanner is stdlib only and offline; TypeScript is matched by regex, not parsed.
4. Apache-2.0.
5. Standalone and vendor-neutral: no product references and no organisation names in incidents.
