# Expected findings for `vulnerable-agent`

Golden set for the skill. A run of `agent-blast-radius` on this folder must produce verdict
**CRITICAL**, boundary **LEAKY**, and every item below, matched by sink and severity (wording may
differ).

## Boundary (must appear)

1. **HIGH**: support agent and billing assistant call a hosted model with no base-URL switch
   (`agent.py:51`, `web/agent.ts:11`). Pattern P11.
2. **HIGH**: ops agent uses the OpenAI Agents SDK with no custom client or tracing opt-out, so its
   model calls and traces go to the vendor by default (`ops_agent.py:33-34`). Patterns P11, P08.
3. **HIGH**: error reporting initialised with an external DSN (`ops_agent.py:9`). Pattern P08.
4. **HIGH**: the issue-tracker MCP server is fetched unpinned on every start (`npx -y`,
   `.mcp.json:3-5`). Pattern P09.
5. **MEDIUM**: the Postgres MCP server is pinned but still fetched at start (`.mcp.json:8-10`).
   Pattern P09.
6. **MEDIUM**: `pip install` in the container CMD (`Dockerfile:6`). The `RUN` at line 4 must
   **not** be flagged. Pattern P09.
7. **MEDIUM**: embedding model downloaded on first use (`agent.py:12`). Pattern P10.

## Blast radius (must appear)

8. **CRITICAL**: ticket or web content → support agent → `run_sql` (`DATABASE_URL`,
   model-written SQL) → any write or delete, no gate. Pattern P02.
9. **CRITICAL**: lethal trifecta in the support agent: `run_sql` + `read_ticket`/`fetch_url` +
   `send_email`/`fetch_url`. Patterns P01, P02.
10. **CRITICAL**: web content → billing assistant → `refund` (`PAYMENTS_SECRET_KEY`), no approval;
    the step limit does not gate it.
11. **CRITICAL**: issue content → coding agent configured by `.mcp.json` → issue tracker writes +
    Postgres MCP as `admin` on `prod-db`. The password is reported as `<redacted>`. Patterns P01, P02.
12. **HIGH**: `run_shell` executes model-written commands with `shell=True`.
13. **HIGH**: `teardown_env` runs `terraform destroy -auto-approve`. Pattern P03.
14. **MEDIUM**: no tracing, audit record or kill switch inside the enclave (D7 absent).
15. **MEDIUM**: support agent has no turn limit. Pattern P07.
16. **MEDIUM**: no backups or deletion protection visible while agents can delete data. Pattern P03.

## Must not appear

- `deploy` reported as ungated. It asks a human before `kubectl apply`.
- Any secret value from `.mcp.json`.
- The Dockerfile `RUN pip install` reported as a boundary crossing.

## Unverifiable statically (must be listed)

- The real scope of `ISSUES_TOKEN`, the DB role behind `DATABASE_URL`, what `OPS_AWS_SECRET` can
  reach, and the payments key's restrictions.
- The issue-tracker MCP server's runtime tool list.
