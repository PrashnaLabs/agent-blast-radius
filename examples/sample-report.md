# Agent blast radius: vulnerable-agent

**Verdict:** CRITICAL · 4 critical, 7 high, 6 medium, 0 low
**Boundary:** LEAKY · 8 paths out
Scanned 2026-11-11 with agent-blast-radius v0.2.0

Every prompt, ticket and database row these agents touch is sent to hosted model APIs, and the
ops agent also ships traces and errors to outside services. None of them would start in a sealed
enclave, because MCP servers and models are fetched at start. Inside the enclave, anyone who can
write a ticket, a web page the agents read, or an issue can make the support agent run any SQL and
email the results, or make the coding agent act as `admin` on `prod-db`.

## Boundary crossings

| What | Where | Crosses | When | Switch | Severity |
|------|-------|---------|------|--------|----------|
| Hosted model (support agent) | `agent.py:51` (`"anthropic:..."`) | whole context: tickets, SQL results, emails | every call | none | HIGH |
| Hosted model (billing) | `web/agent.ts:11` | whole context: web pages, charge ids | every call | none | HIGH |
| Hosted model + default trace export (ops) | `ops_agent.py:33-34`: Agents SDK with no custom client and no `set_tracing_disabled` | whole context, plus traces of every tool call | every run | none | HIGH |
| Error reporting | `ops_agent.py:9` (`sentry_sdk.init`, `SENTRY_DSN`) | stack traces, local variables | on error | none | HIGH |
| Issue-tracker MCP, unpinned | `.mcp.json:3-5` (`npx -y @acme/mcp-issue-tracker`) | code in, newest release | every start | none | HIGH |
| Postgres MCP, pinned | `.mcp.json:8-10` (`npx -y ...@0.6.2`) | code in | every start | pin exists; no pre-install | MEDIUM |
| `pip install` at container start | `Dockerfile:6` (CMD) | code in | every boot | none | MEDIUM |
| Embedding model on first use | `agent.py:12` (`SentenceTransformer(...)`) | model files in | first use | none (`HF_HUB_OFFLINE` not set) | MEDIUM |

`Dockerfile:4` (`RUN pip install`) runs at build time and is fine if the image is built outside and
imported.

- Patterns: P11 (hosted model), P08 (telemetry), P09 (code fetched at start), P10 (first-use download)
- OWASP: LLM02:2025 for context leaving the enclave, ASI04 for code fetched at start
- Fix, in order:
  1. Point every model client at the in-enclave endpoint (`base_url` / `createOpenAI({ baseURL })`, or a custom client for the Agents SDK).
  2. Call `set_tracing_disabled(True)` and drop `sentry_sdk.init`, or point it at a self-hosted collector.
  3. Pre-install pinned MCP packages in the image and launch them with `node`/`python`, not `npx -y`.
  4. Move the CMD install into `RUN`.
  5. Vendor the embedding model and set `HF_HUB_OFFLINE=1`.

## Toxic paths

1. **CRITICAL**: ticket or web page → support agent → `run_sql` (`DATABASE_URL`, model-written SQL)
   → any write, delete or drop, no gate
   - Evidence: `agent.py:18` (ticket text returned to the model), `agent.py:24` (any URL),
     `agent.py:30-31` (`conn.execute(query)` on model text), `agent.py:50-53` (same agent holds all
     three)
   - Pattern: P02 (researcher disclosure)
   - OWASP: ASI01, ASI02, ASI03
   - Fix: remove `run_sql` from the agent that reads tickets. Replace it with typed read tools
     (`get_customer(id)`) on a read-only role. Run `cleanup_old_records` as a scheduled job, not a
     tool.

2. **CRITICAL**: lethal trifecta in the support agent: private data (`run_sql`) + untrusted content
   (`read_ticket`, `fetch_url`) + a way out (`send_email` to any address, `fetch_url` to any host,
   and the hosted model itself)
   - Evidence: `agent.py:31`, `agent.py:18`, `agent.py:24`, `agent.py:46`, `agent.py:51`
   - Pattern: P01, P02 (researcher disclosure)
   - OWASP: ASI01, ASI02, LLM02:2025
   - Fix: break one leg. `send_email` only replies to the ticket's requester, taken from the ticket
     system; `fetch_url` gets a host allowlist of in-enclave hosts; the model endpoint moves inside
     the enclave.

3. **CRITICAL**: web page → billing assistant → `refund` (`PAYMENTS_SECRET_KEY`) → refunds any
   charge, no approval
   - Evidence: `web/agent.ts:18` (`fetch(url)` on any URL), `web/agent.ts:23`
     (`payments.refunds.create`), `web/agent.ts:7` (full secret key). `stopWhen: stepCountIs(20)` at
     `web/agent.ts:13` is a limit, not a gate.
   - Pattern: no known pattern
   - OWASP: ASI01, ASI02, ASI03
   - Fix: remove `execute` from `refund` so the call returns to the app for a human decision (or
     set the SDK's per-tool approval). Use a restricted key and a server-side amount cap.

4. **CRITICAL**: issue content → coding agent configured by `.mcp.json` → issue-tracker MCP
   (writes) + Postgres MCP as `admin` on `prod-db`
   - Evidence: `.mcp.json:3` (issue tracker reads and writes issues), `.mcp.json:8-10` (Postgres
     server, admin connection string with password in args, `<redacted>`)
   - Pattern: P01, P02 (researcher disclosure)
   - OWASP: ASI01, ASI03, ASI04
   - Fix: remove the production database from a developer agent's config. If it is needed, point
     it at a read-only role on a replica, pass the URL by env var, and rotate the committed
     password.

## Reach map

| Agent | Tool | Reaches (credential) | Model controls | Irreversible | Egress | Gate |
|-------|------|----------------------|----------------|--------------|--------|------|
| support (`agent.py:50`) | `read_ticket` | helpdesk API | ticket id | no | GET | none |
| support | `fetch_url` | any host | URL | no | GET to any URL | none |
| support | `run_sql` | `DATABASE_URL` | whole SQL text | yes | no | none |
| support | `cleanup_old_records` | `DATABASE_URL` | nothing | yes (DELETE) | no | none |
| support | `send_email` | internal SMTP | recipient, body | yes | any address | none |
| ops (`ops_agent.py:33`) | `run_shell` | process env, filesystem, network | whole command | yes | yes | `max_turns=50` only |
| ops | `teardown_env` | `OPS_AWS_SECRET` as AWS key | env name | yes (destroy) | no | **bypassed** (`-auto-approve`) |
| ops | `deploy` | kubectl context | service name | yes | no | human approval in code (`ops_agent.py:28`) |
| billing (`web/agent.ts:10`) | `readPage` | any host | URL | no | GET to any URL | step limit only |
| billing | `refund` | `PAYMENTS_SECRET_KEY` | charge id | yes | no | step limit only |
| coding agent (`.mcp.json`) | issue-tracker MCP | `ISSUES_TOKEN` | runtime tools | unknown | yes | none in repo |
| coding agent (`.mcp.json`) | Postgres MCP | `admin@prod-db` | SQL | unknown | no | none in repo |

## Findings by dimension

### D1 Untrusted input: Exposed
- Ticket bodies (`agent.py:18`), arbitrary web pages (`agent.py:24`, `web/agent.ts:18`) and issues
  through the MCP server (`.mcp.json:3`) reach agents that hold irreversible tools. See toxic
  paths 1–4.

### D2 Reach: Exposed
- **HIGH**: `run_shell` runs model-written commands with `shell=True`, so it reaches everything the
  process can: the environment (including the AWS key that `teardown_env` places in it at
  `ops_agent.py:21`), the filesystem and the internal network.
  - Evidence: `ops_agent.py:12-15`, `ops_agent.py:21`
  - Pattern: no known pattern
  - OWASP: ASI05, ASI03
  - Fix: remove `run_shell`. Expose the two or three commands ops actually needs as typed tools.

### D3 Privilege fit: Exposed
- `admin` credential for `prod-db` committed in `.mcp.json:10`. Counted under toxic path 4.
- Scope of `DATABASE_URL`, `OPS_AWS_SECRET` and `PAYMENTS_SECRET_KEY`: Unknown (see below).

### D4 Irreversibility: Exposed
- **HIGH**: `teardown_env` runs `terraform destroy -auto-approve` on a model-chosen environment.
  The task says "clean up staging", but nothing limits `env` to staging.
  - Evidence: `ops_agent.py:18-22`, `ops_agent.py:34`
  - Pattern: P03 (first-person postmortem), P04 (press report)
  - OWASP: ASI02, ASI03
  - Fix: drop `-auto-approve`; have the tool run `terraform plan -destroy` and return the plan; a
    human applies it. Restrict `env` to an enum of non-production names, and use separate cloud
    credentials per environment.

### D5 Egress: Exposed
- `send_email` (any recipient) and `fetch_url`/`readPage` (any URL) let the model pick where data goes.
  Counted under toxic paths 2 and 3.

### D6 Gates: Partial
- `deploy` asks a human before `kubectl apply` (`ops_agent.py:28`), enforced in code. This is the
  only approval gate.
- **MEDIUM**: the support agent has no turn or recursion limit (`agent.py:50-53`).
  - Pattern: P07 (press report)
  - OWASP: ASI08
  - Fix: pass `recursion_limit` in the run config.

### D7 Identity & audit: Exposed
- **MEDIUM**: no agent traces tool calls inside the enclave, records who triggered an irreversible action, or has a
  kill switch. The only tracing in the repo is the vendor default export, which crosses the
  boundary (see above) and is not an audit record.
  - Pattern: no known pattern
  - OWASP: ASI10, ASI03
  - Fix: trace every tool call to an in-enclave collector (OpenTelemetry), with the acting agent and
    end user. Write an audit record for each refund, delete, destroy and email. Check a
    kill-switch flag before every irreversible tool.

## Detect & recover

- **MEDIUM**: no backups, snapshots or deletion protection are visible in the repo, while three
  agents can delete data or infrastructure.
  - Pattern: P03 (first-person postmortem): the snapshots were deleted along with the database.
  - OWASP: ASI08
  - Fix: enable deletion protection on the production database. Keep backups where the agents'
    credentials cannot reach, and test a restore.

## Unverifiable statically

- The database role behind `DATABASE_URL`: check its grants.
- What `OPS_AWS_SECRET` can reach: check the IAM policy, especially whether it covers production.
- Restrictions on `PAYMENTS_SECRET_KEY`: check whether it is a restricted key with an amount cap.
- The scopes of `ISSUES_TOKEN`.
- The issue-tracker MCP server's runtime tool list and descriptions.
- Whether the enclave's network actually blocks the hosts above. This report assumes nothing
  outside is reachable, and lists what would break or leak if something is.

## Method

- Inventory: scanner v0.2.0, 6 files, sha256 of the inventory JSON
  `45a95b8f15921ddd7c65e71ca78b50847bc8910046926f720b2c4e192a0d751c`
- Frameworks: langchain, langgraph, openai_agents, vercel_ai, plus MCP client config and Dockerfile
- Read by hand: `agent.py`, `ops_agent.py`, `web/agent.ts`, `.mcp.json`, `.env.example`, `Dockerfile`
- Rubric v0.2.0, patterns v0.2.0
- Static review only. It does not prove the absence of runtime behaviour.
