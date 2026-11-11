# Rubric (v0.2.0)

Two questions, scored separately:
1. **Boundary (D8):** does the agent need, or reach, anything outside the air-gapped enclave?
2. **Blast radius (D1–D7):** inside the enclave, what can an attacker do through the agent? The
   attacker is an insider, a compromised host, or poisoned content that got in through an
   approved channel (documents, tickets, imports).

Scoring is a lookup from evidence. If the evidence is not in the repo, the state is **Unknown**:
never assume a control exists. Report Unknown as a gap and put it under "Unverifiable statically".

## Dimensions

Score each dimension **per agent**, and per tool where noted.

| State | Meaning |
|-------|---------|
| Contained | Evidence shows the control is present and covers every tool it should |
| Partial | Present for some tools or paths, missing for others |
| Exposed | Evidence shows the risk exists and no control covers it |
| Unknown | The decision lives outside the repo (IAM policy, runtime config, remote MCP server) |

### D1 Untrusted input: what attacker-controllable text reaches the context?

Sources: web pages, search results, tickets, emails, chat messages, issues and PRs, uploaded
documents, RAG chunks from user-writable stores, MCP tool outputs, MCP tool *descriptions*, and
memory written from any of these.

- Contained: no untrusted source reaches an agent that holds irreversible or egress tools. Or the
  untrusted content goes to a separate, tool-less agent whose output is treated as data.
- Exposed: the same agent reads untrusted content and holds irreversible or egress tools.

### D2 Reach: what can the agent touch?

List every credential, connection and endpoint each tool uses. Credentials are named by variable
and location, never by value. Include indirect reach: a shell tool reaches everything the process
user can reach; a cloud SDK with default credentials reaches the whole role; the cloud metadata
endpoint reaches instance credentials.

- Contained: each tool's reach is bounded to what its task needs.
- Exposed: a general-purpose tool (shell, raw SQL, HTTP with arbitrary URL, `eval`) or ambient
  credentials (default cloud chain, process env with prod secrets) are reachable.

### D3 Privilege fit: is each credential scoped to the task?

- Contained: read-only roles for read tools; separate credentials per tool or per environment;
  tokens scoped to named resources.
- Exposed: admin or owner DB roles, keys that bypass row-level security, root or
  org-wide tokens, a staging agent that can resolve a prod credential, one credential shared
  by read and destructive tools.
- Unknown: the credential's real scope is set outside the repo. Say so and name what to check.

### D4 Irreversibility: which reachable actions cannot be undone?

Destructive SQL (DROP, TRUNCATE, DELETE, ALTER), arbitrary SQL, shell, file deletion, infra
destroy, deploys, force push, payments, refunds and transfers, sending email or messages, and
anything that signs a transaction.

- Contained: every irreversible action is behind a D6 gate, or the action is soft (delayed delete,
  trash, reversible) by construction.
- Exposed: an irreversible action runs on the model's decision alone.

### D5 Egress: where can data leave?

Outbound HTTP (including GET with a model-chosen URL, which leaks through the query string),
email, messaging, webhooks, PR, issue and comment creation, uploads, browser automation.

- Contained: egress goes only to an allowlist of hosts or recipients, or it needs approval.
- Exposed: the model chooses the destination.

### D6 Gates: what stands between intent and action?

Human approval, allowlists, sandboxing, dry-run or plan-then-apply, turn and recursion limits,
spend caps.

- Contained: every D4 action has a human approval or a hard technical bound, and the agent has a
  turn limit.
- Partial: some irreversible tools are gated and others are not, or only a turn limit exists.
- Exposed: there are no gates, or a gate is bypassed (`auto-approve`, `--yes`,
  `bypassPermissions`, `dangerously*`).

A bypass flag on an irreversible command counts as **no gate**, and is a finding of its own.

### D7 Identity & audit: can you prove who did what, and stop it?

- Contained: tool calls are traced with the acting agent and the end user; there is an audit
  record per irreversible action; there is a kill switch and a credential rotation path.
- Exposed: no tracing of tool calls, no audit record, no way to stop a running agent.

### D8 Boundary: does anything need or reach outside the enclave?

List every path out, and say for each one what crosses, when, and how to seal it:

- **Hosted model:** model clients or `provider:model` strings that point at a hosted API with no
  base-URL or local-model switch (P11). Everything in the context crosses.
- **Telemetry and tracing:** SaaS tracing hosts, error reporters, analytics, and framework
  telemetry that is on by default (P08). Prompts and tool output usually cross.
- **Code fetched at start:** MCP servers or tools launched with `npx`, `uvx` or `pipx`, and
  installs in CMD, ENTRYPOINT or start scripts (P09). Installs in a Dockerfile `RUN` happen at build
  time and are fine if the image is built outside and imported.
- **Files fetched on first use:** model weights, tokenizers, corpora, browser binaries (P10).
- **SaaS connectors and web tools:** email, CRM, search, browsing, remote MCP servers. These are
  D5 egress too.
- **Hard-coded external hosts:** the scanner's `external_hosts` list. Decide for each one whether a
  runtime path uses it.

States:
- Sealed: no runtime path leaves the enclave, or every one is behind a switch that defaults off,
  and an offline mode exists for models and files.
- Leaky: at least one context-bearing path (hosted model, telemetry, SaaS connector) is on by
  default.
- Brittle: nothing leaks, but the agent fetches code or files at start, so it breaks in a sealed
  enclave or pulls whatever a mirror serves.

### Detect & recover (secondary)

Backups stored outside the agent's reach (a delete through the agent's credential must not be able
to delete the backups), deletion protection, alerting on irreversible tool calls, a restore that
has been tested. Score this only where it changes the damage of a D4 finding.

## Toxic paths

A toxic path is a chain:

```
untrusted source (D1) → agent → tool with reach (D2/D3) → irreversible action (D4) or egress (D5)
```

with no D6 gate on the way. Trace one path per distinct sink. Name each hop with `file:line`.

**The lethal trifecta** is the special case where one agent has all three of: access to private
data, exposure to untrusted content, and a way to send data out. It is always Critical.

## Severity

| Severity | Rule |
|----------|------|
| Critical | Lethal trifecta in one agent. Or an irreversible action reachable from untrusted input with no gate. Or a production credential reachable from a non-production agent or task |
| High | An irreversible action with no gate, even without untrusted input. An over-scoped credential (D3 Exposed). A gate bypass flag on an irreversible command. Arbitrary code or shell execution |
| Medium | Egress with a model-chosen destination and no allowlist. No tracing of tool calls. No turn limit or spend cap. Backups reachable by the agent's credential |
| Low | Unpinned MCP server or tool package versions. Third-party tool descriptions loaded without review. Hygiene |

D8 severities:

| Severity | Rule |
|----------|------|
| High | A context-bearing path out of the enclave that is on by default: hosted model with no base-URL switch, SaaS tracing or telemetry, a remote MCP server. Unpinned code fetched at start |
| Medium | Pinned code or files fetched at start or on first use. Web, search or SaaS tools without a switch to turn them off |
| Low | External hosts in code that no runtime path uses (docs links, comments, examples) |

When unsure between two severities, pick the higher one and say why in one line.

## Verdict

| Verdict | Rule |
|---------|------|
| CRITICAL | At least one Critical finding |
| EXPOSED | No Critical, at least one High |
| CONTAINED | No Critical or High, and D6 and D7 are Contained for every irreversible tool |

If neither CRITICAL nor CONTAINED fits because there are no Critical or High findings but some
dimensions are still Unknown, the verdict is EXPOSED. List what was unknown.

The boundary gets its own line: **Boundary: SEALED | BRITTLE | LEAKY**, using the D8 states above.
An agent can be CONTAINED and LEAKY at the same time; report both.

## Finding format

Every finding has all five parts. A finding missing one is not reported.

1. **What:** one sentence, naming the agent, the tool and the sink.
2. **Evidence:** `file:line` for each hop.
3. **Pattern:** a pattern id from `patterns.md` whose mechanism matches, with its basis label.
   If none matches, write "no known pattern". Never stretch a pattern to fit.
4. **OWASP:** one or more ASI ids from `owasp-asi.md`.
5. **Fix:** the smallest change that breaks the path. Prefer, in order: remove the tool; narrow the
   credential; add an allowlist; add a human approval; add a limit.
