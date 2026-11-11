---
name: agent-blast-radius
description: >
  Checks an AI agent codebase for vulnerabilities before it runs in an air-gapped, on-prem or
  otherwise isolated environment. Finds every path that crosses the boundary (hosted model APIs,
  telemetry that phones home, packages or models fetched at start, SaaS connectors, external
  hosts), then maps the agent's blast radius inside the enclave: tools, credentials, irreversible
  actions, egress and approval gates, and the toxic paths from untrusted input to destructive
  actions or data leaks. Writes BLAST_RADIUS.md with file:line evidence, failure patterns and
  OWASP agentic (ASI) ids. Use when asked whether an agent is ready for an air-gapped, offline,
  sovereign or on-prem deployment, to audit an agent's security, permissions, tool access, least
  privilege or prompt-injection exposure, or "is my agent safe to ship". Works on
  LangChain/LangGraph, deepagents, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Vercel AI SDK, raw
  tool loops and MCP configs. Read-only: never runs the target's code.
allowed-tools: Read, Grep, Glob, Bash(python3:*), Write
---

# Agent blast radius

Two questions for an agent that will run inside an air-gapped or isolated environment:

1. **Boundary:** does anything in it need, or reach, the outside world?
2. **Blast radius:** inside the enclave, if the agent is steered by poisoned content, an insider or
   a compromised host, what can it do?

An air gap does not make an agent safe. It removes the network path out. It does not limit what
the agent can do to the systems inside, and agents that quietly call hosted models, send
telemetry or download packages either break in the enclave or open the gap again.

## Safety contract (do not break)

- **Read-only.** Never run, import, build or install the target's code. Never call its endpoints,
  connect to its databases or use its credentials. The only command you run is the bundled scanner.
- **No secret values.** Name a credential by variable and location (`DATABASE_URL` at
  `src/db.py:12`). Never print, quote or summarise its value, even if you read a file containing
  it. If a snippet would show a secret, replace it with `<redacted>`.
- **One write.** The report file `BLAST_RADIUS.md` at the repo root. If it already exists, ask
  before overwriting.
- **Evidence or nothing.** Every claim cites `file:line`. What the repo cannot show goes under
  "Unverifiable statically"; never present a guess as a finding.

## Workflow

### 1. Inventory

Run the scanner from this skill's base directory against the repo root (or the agent's
subdirectory in a large monorepo):

```bash
python3 -I <skill-base-dir>/scripts/inventory.py <repo-root> > /tmp/blast-radius-inventory.json
```

It prints JSON with:
- `frameworks`
- `hits`, each with a category, rule and `file:line`. Categories:
  - context: `framework`, `tool_definition`, `mcp_server`
  - boundary: `boundary` (hosted_model, telemetry, runtime_fetch), `boundary_control` (offline switches, base-URL overrides)
  - blast radius: `untrusted_input`, `credential`, `irreversible`, `egress`, `gate`, `gate_bypass`, `prompt_only_gate`, `identity_audit`, `recovery`
- `external_hosts`: hosts that appear in code, with a count and first location.
- `absent`: dimensions with no evidence at all.
- `counts` and `truncated`: rules capped at 50 hits, with tool-defining files listed first.

MCP entries include `pinned` and `fetches_at_runtime`. Treat hits as **pointers, not findings**.
The scanner matches text, so it has false positives and misses. Step 2 and step 3 settle them.

If `python3` is missing, do the same sweep with Grep and Glob, using the categories above, and say so in the
report's Method section.

### 2. Boundary (D8)

Walk every path out of the enclave. Start from the `boundary` hits, MCP entries with
`fetches_at_runtime`, and `external_hosts`. Then use the D8 table in `references/frameworks.md`
to catch defaults the code does not spell out, such as tracing that is on unless disabled. For each path,
record:
- **What crosses:** whole prompts and context, tool output, metrics only, or code coming in.
- **When:** every call, at start, on first use, or only when a feature is used.
- **The switch:** an existing base-URL, offline flag or opt-out, or "none".

A Dockerfile `RUN` install happens at build time and is fine if the image is built outside and
imported. CMD, ENTRYPOINT and start scripts run inside the enclave.

### 3. Map reach (read the code)

For each agent, find its tools. Start from `tool_definition` and `mcp_server` hits, then follow
`references/frameworks.md`. Open every tool and record:

- **What it can touch:** the client, credential and endpoint it uses. Follow helper functions; a
  tool that calls `db.run(query)` reaches whatever `db` was built with.
- **Whether the model controls the dangerous part:** the SQL text, the shell command, the URL,
  the recipient, the amount.
- **Irreversible actions (D4) and egress (D5)** it can perform.
- **Gates (D6) on the path:** an approval enforced in code that covers *this* tool, an allowlist,
  a limit. A gate on a different tool does not count. A bypass flag (`auto-approve`,
  `bypassPermissions`) cancels a gate. A `prompt_only_gate` hit ("only call this after the user
  confirms") is **not** a gate: check whether the server verifies the approval.
- **Untrusted content (D1) it returns to the model.** Tool output is model input. In an enclave,
  untrusted content arrives through approved channels: imported documents, tickets, emails,
  shared drives, other agents.

Also check reach that is not a tool: a shell or code tool reaches the process environment, the
filesystem and internal network services. Default cloud credential chains reach the whole role.

### 4. Trace toxic paths

Connect every D1 source to every D4 or D5 sink inside the same agent, or across agents when one
agent's output becomes another's input. A path is toxic when no enforced D6 gate sits on it. Check every
agent for the lethal trifecta: private data, untrusted content and a way out. Inside an enclave,
"a way out" includes any D8 crossing and any internal sink the attacker can read.

### 5. Score

Use `references/rubric.md` as a lookup: dimension states, severity, verdicts. For each finding:

- **Pattern:** pick from `references/patterns.md` only when the mechanism matches; otherwise
  write "no known pattern".
- **OWASP:** take ids from `references/owasp-asi.md`.
- **Fix:** give the smallest change that breaks the path, in this order of preference: remove the
  tool, narrow the credential, add an allowlist, add an enforced approval, add a limit. For D8:
  point to a local endpoint, turn on the offline flag, vendor the file, or pin and pre-install.
  Name the framework's own mechanism.

### 6. Write `BLAST_RADIUS.md`

Use exactly this structure:

```markdown
# Agent blast radius: <repo name>

**Verdict:** <CRITICAL | EXPOSED | CONTAINED> · <n> critical, <n> high, <n> medium, <n> low
**Boundary:** <SEALED | BRITTLE | LEAKY> · <n> paths out
Scanned <YYYY-MM-DD> with agent-blast-radius v0.2.0

<two sentences: what leaves the enclave, and the worst thing an attacker inside can do through the agent>

## Boundary crossings

| What | Where | Crosses | When | Switch | Severity |
|------|-------|---------|------|--------|----------|

## Toxic paths

1. **CRITICAL**: <source> → <agent> → <tool> (<credential>) → <sink>, no gate
   - Evidence: `file:line`, `file:line`
   - Pattern: <P0x> (<basis>)
   - OWASP: ASI01, ASI02
   - Fix: <smallest change>

## Reach map

| Agent | Tool | Reaches (credential) | Model controls | Irreversible | Egress | Gate |
|-------|------|----------------------|----------------|--------------|--------|------|

## Findings by dimension

### D1 Untrusted input: <state>
... one bullet per finding, same five parts as above, then D2 to D7

## Detect & recover

## Unverifiable statically

- <what could not be proven from the repo, and exactly where to check it>

## Method

- Inventory: scanner v<version>, <files_scanned> files, sha256 of the inventory JSON <hash>
- Frameworks: <list>
- Read by hand: <files opened in steps 2 and 3>
- Rubric v0.2.0, patterns v0.2.0
- Static review only. It does not prove the absence of runtime behaviour.
```

Compute the hash with `shasum -a 256 /tmp/blast-radius-inventory.json` (or `sha256sum`).

### 7. Report back

In chat give: the verdict and boundary lines, the top three findings in one line each, and the
path to `BLAST_RADIUS.md`. Offer to explain any finding in more detail. Do not change the target code unless the
user asks, and treat that as a new task.

## Calibration

- An agent with no irreversible tools and no egress can still be EXPOSED through D3, for example
  a read tool holding an owner credential. Report it.
- An irreversible tool behind an approval **enforced in code** is not a toxic path. Still list it
  in the reach map.
- Prompt instructions and UI-only confirmation cards are not gates. Report them as D6 gaps.
- Internal-only agents still count. A compromised laptop or an insider can drive an internal agent,
  and the agent's reach becomes theirs.
- An agent that leaks nothing but fetches packages at start is BRITTLE, not SEALED. It will fail
  in a real air gap.
- Do not pad. A small repo may have one finding. CONTAINED and SEALED are valid verdicts when the
  evidence supports them.
