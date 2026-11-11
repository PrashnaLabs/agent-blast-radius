# vulnerable-agent

A **deliberately vulnerable** set of agents, used to test agent-blast-radius. Never deploy it.
It holds no real credentials, and every company and package name is made up.

- `agent.py`: LangGraph support agent. It reads tickets and web pages, runs raw SQL, sends email,
  calls a hosted model and downloads an embedding model on first use.
- `ops_agent.py`: OpenAI Agents SDK ops agent. It has a shell tool, an auto-approved
  `terraform destroy`, one gated deploy, and external error reporting.
- `web/agent.ts`: Vercel AI SDK billing assistant that reads web pages and issues refunds.
- `.mcp.json`: an issue-tracker MCP server fetched unpinned on every start, and a Postgres MCP server
  with a password in its args.
- `Dockerfile`: one build-time install (fine) and one install at container start (not fine).

`expected.md` lists what the audit must find.
