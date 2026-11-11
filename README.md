# agent-blast-radius

**Check your agent for vulnerabilities before it goes into an air-gapped environment.**

`agent-blast-radius` is an agent skill that reads an AI agent's codebase and answers two questions:

1. **Boundary:** does anything in this agent need, or reach, the outside world? That covers hosted
   model APIs, telemetry that phones home, packages and models fetched at start, SaaS connectors
   and hard-coded external hosts.
2. **Blast radius:** inside the enclave, if the agent is steered by a poisoned document, an
   insider or a compromised host, what can it do?

It writes a `BLAST_RADIUS.md` report with `file:line` evidence, the failure pattern each finding
matches, OWASP agentic (ASI) ids, and the smallest fix for each path.

## Why air-gapped agents need this

An air gap removes the network path out. It does not make an agent safe.

- **Agents leak by default.** Hosted model clients send the whole context out on every call.
  Several frameworks export traces or telemetry to a vendor unless you opt out. In a sealed
  enclave these calls fail, and in a leaky one the data leaves.
- **Agents fetch code at start.** `npx -y some-mcp-server`, `pip install` in a start script, and
  model downloads on first use all break the first time the agent boots inside the gap. Or, with a
  mirror, they run whatever the registry served that day.
- **The damage happens inside.** Documented failures show agents deleting production databases and
  their backups with one call, leaking private data after reading a poisoned ticket, and serving as
  a path from one compromised laptop to other engineers' machines. None of these needed the
  internet. They needed an agent with more reach than its task.

## What you get

From [`examples/sample-report.md`](examples/sample-report.md), a run on the deliberately vulnerable
[`examples/vulnerable-agent`](examples/vulnerable-agent):

```markdown
**Verdict:** CRITICAL · 4 critical, 7 high, 6 medium, 0 low
**Boundary:** LEAKY · 8 paths out

| What | Where | Crosses | When | Switch | Severity |
| Hosted model (support agent) | agent.py:51 | whole context: tickets, SQL results, emails | every call | none | HIGH |
| Issue-tracker MCP, unpinned | .mcp.json:3-5 (npx -y ...) | code in, newest release | every start | none | HIGH |

1. **CRITICAL**: ticket or web page → support agent → run_sql (DATABASE_URL, model-written SQL)
   → any write, delete or drop, no gate
   - Pattern: P02 · OWASP: ASI01, ASI02, ASI03
   - Fix: remove run_sql from the agent that reads tickets; typed read tools on a read-only role.
```

The report also includes a reach map (agent × tool × credential × gate), findings for each
dimension, a detect-and-recover section, and a list of what static reading cannot prove.

## Install

### Claude Code (plugin)

Inside Claude Code 2.1.275 or later:

```
/plugin install agent-blast-radius --marketplace PrashnaLabs/agent-blast-radius
```

On older versions, add the marketplace first, then install:

```
/plugin marketplace add PrashnaLabs/agent-blast-radius
/plugin install agent-blast-radius@prashnalabs
```

The repository is private for now. Installing needs read access to it, and Claude Code clones it with your
existing git credentials, so make sure `git clone git@github.com:PrashnaLabs/agent-blast-radius.git`
works for you first (SSH key, or `gh auth login`). If background updates cannot reach it, export a
`GITHUB_TOKEN` with read access.

### Any Agent Skills host (manual)

Copy the skill folder into your agent's skills directory.

```bash
git clone git@github.com:PrashnaLabs/agent-blast-radius.git
cp -r agent-blast-radius/skills/agent-blast-radius ~/.claude/skills/          # all projects
# or: cp -r agent-blast-radius/skills/agent-blast-radius <your-repo>/.claude/skills/
```

The folder follows the Agent Skills layout (`SKILL.md` + `references/` + `scripts/`), so other
hosts that read Agent Skills can load it from their own skills directory. The skill itself needs no
network access.

## Use

In the repo you want audited, ask your agent:

```
is this agent ready for an air-gapped deployment?
```

or "audit my agent's blast radius", or "is this agent safe to ship?".

The scanner also runs on its own and prints JSON evidence:

```bash
python3 skills/agent-blast-radius/scripts/inventory.py path/to/repo
```

## What it checks

| | Dimension | Question |
|-|-----------|----------|
| D8 | Boundary | What needs or reaches outside the enclave, and is there a switch to seal it? |
| D1 | Untrusted input | What attacker-controllable text reaches the context? |
| D2 | Reach | What systems, data and credentials can the agent touch? |
| D3 | Privilege fit | Is each credential scoped to the task? |
| D4 | Irreversibility | Which reachable actions cannot be undone? |
| D5 | Egress | Where can data go? |
| D6 | Gates | What stands between the model's decision and the action, enforced in code? |
| D7 | Identity & audit | Can you prove who did what, and stop it? |

The report has two verdict lines:
- **Boundary:** SEALED (nothing crosses), BRITTLE (nothing leaks, but something is fetched at
  start), or LEAKY (context leaves by default).
- **Blast radius:** CRITICAL (a toxic path or lethal trifecta), EXPOSED (high-severity reach), or
  CONTAINED (every irreversible action is gated and audited).

The full rules are in [`references/rubric.md`](skills/agent-blast-radius/references/rubric.md).

Frameworks: LangChain, LangGraph, deepagents, CrewAI, OpenAI Agents SDK, Claude Agent SDK, Vercel
AI SDK, raw tool-calling loops, and MCP client configs, in Python and TypeScript, plus Dockerfiles and
start scripts.

## How it works

Two halves keep the judgment honest:

1. **`scripts/inventory.py`**: a deterministic, read-only scanner that uses only the Python
   standard library and needs no network. It never imports or runs your code and never prints
   secret values; credentials appear by name and location only. It lists every external host
   found in code, and the same repo always gives the same JSON.
2. **`SKILL.md`**: the agent reads each tool and boundary crossing the scanner points at, decides
   what really crosses or is reachable, traces the toxic paths, and scores them against a fixed
   rubric. Whether a send tool's "only call this after the user confirms" is enforced by the server
   or only written in a docstring needs reading the code. A linter cannot decide it.

Findings cite patterns from
[`references/patterns.md`](skills/agent-blast-radius/references/patterns.md): documented agent
failures and risky library defaults, described without naming the organisations involved.

## Safety

- Read-only. The only file it writes is `BLAST_RADIUS.md`, and it asks before overwriting one.
- It never runs, installs or connects to anything in the target repo.
- Secret values are never printed.
- The scanner runs fully offline.

## Limits

- Static only. It cannot see network policy, IAM policies, token scopes, or the tools a remote
  MCP server serves at runtime. These go under "Unverifiable statically", with where to check.
- The scanner matches line by line, so it can miss calls split across lines. The reading step
  covers most of these.
- The scanner takes about 1 s of CPU per MB of source. In a large monorepo, point it at the agent's
  directory.

## Development

```bash
uvx pytest -q tests
```

`tests/test_inventory.py` checks the scanner against the fixture: every expected hit and no extra
hits, the build-time versus runtime install rule, the external host summary, secret redaction,
vendor-directory skipping and the per-rule cap.
[`examples/vulnerable-agent/expected.md`](examples/vulnerable-agent/expected.md) is the golden
set for the skill itself.

## License

Apache-2.0
