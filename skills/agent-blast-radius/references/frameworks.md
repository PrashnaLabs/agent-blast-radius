# Where reach, gates and boundary crossings live, per framework

Use this to find what the scanner points at. APIs move fast: when a name below is not in the
repo, check the version pinned in its lockfile before concluding that a control is missing.

## Boundary (D8) quick reference

| Framework | Model endpoint switch | Telemetry or tracing to check |
|-----------|-----------------------|-------------------------------|
| LangChain / LangGraph / deepagents | `base_url` on the chat model, or a local provider (`ChatOllama`, OpenAI-compatible server) | LangSmith tracing turns on when `LANGSMITH_TRACING` / `LANGCHAIN_TRACING_V2` is set |
| CrewAI | `LLM(base_url=...)` | Anonymous telemetry is on by default in documented versions; look for its opt-out (`OTEL_SDK_DISABLED` / `CREWAI_DISABLE_TELEMETRY`) |
| OpenAI Agents SDK | custom client via `set_default_openai_client` or a model provider | Traces export to the vendor by default; look for `set_tracing_disabled(True)` or `OPENAI_AGENTS_DISABLE_TRACING` |
| Claude Agent SDK | `ANTHROPIC_BASE_URL` | Check the host CLI's telemetry settings |
| Vercel AI SDK | `createOpenAI({ baseURL })` and similar | Telemetry is opt-in (`experimental_telemetry`) |
| Raw SDK clients | `base_url` / `baseURL` argument or env var | Whatever the app adds |
| Embeddings / Hugging Face | local model path plus `HF_HUB_OFFLINE=1` or `local_files_only=True` | none by default; downloads on first use (P10) |
| Vector stores | embedded or self-hosted mode | some ship anonymous telemetry on by default (`ANONYMIZED_TELEMETRY`) |

## LangChain / LangGraph / deepagents (Python, JS)

- **Tools:** `@tool` functions, `StructuredTool`, `BaseTool` subclasses; the list passed to
  `create_react_agent(..., tools=[...])`, `create_agent(...)`, `create_deep_agent(...)`, or
  `bind_tools`. Toolkits (`SQLDatabaseToolkit`, `GmailToolkit`, `PlayWrightBrowserToolkit`,
  `ShellTool`) expand to several tools; list each one.
- **Gates:** `interrupt(...)` inside a node or tool, `interrupt_before`/`interrupt_after` on
  compile, `HumanInTheLoopMiddleware`, deepagents `interrupt_on={...}`. An interrupt only gates
  the tools it names.
- **Limits:** `recursion_limit` in the run config.
- **Reach traps:** `SQLDatabase.from_uri(...)` with a write-capable role; `requests` tools with no
  URL allowlist; filesystem backends rooted at `/`.

## CrewAI (Python, YAML)

- **Tools:** `tools=[...]` on `Agent`; `@tool` functions; `BaseTool` subclasses; agents and tasks
  may be declared in `config/agents.yaml` and `config/tasks.yaml`.
- **Gates:** `human_input=True` on a `Task` asks for review of the task output. It runs after the
  tools have already run, so it does not gate tool calls.
- **Limits:** `max_iter`, `max_rpm`, `max_execution_time` on `Agent`.
- **Reach traps:** `allow_code_execution=True`; `CodeInterpreterTool`.

## OpenAI Agents SDK (Python `agents`, JS `@openai/agents`)

- **Tools:** `@function_tool` functions, hosted tools (`WebSearchTool`, `FileSearchTool`,
  `ComputerTool`, `CodeInterpreterTool`), MCP servers attached to the agent, and agents used as
  tools via `as_tool()` or handoffs. A handoff gives the next agent's tools to the conversation.
- **Gates:** approval on tool calls exists in recent versions; look for `needs_approval`. Input
  and output guardrails check text, not tool side effects.
- **Limits:** `max_turns` on `Runner.run`.

## Claude Agent SDK (Python `claude_agent_sdk`, TS `@anthropic-ai/claude-agent-sdk`)

- **Tools:** built-in tools (Bash, file edit, web fetch), custom tools via in-process MCP servers,
  and external MCP servers from options or `.mcp.json`.
- **Gates:** `allowed_tools`/`disallowed_tools`, `can_use_tool` callback, `PreToolUse` hooks,
  `permission_mode`. `bypassPermissions` removes the gates.
- **Limits:** `max_turns`.

## Vercel AI SDK (TS `ai`, `@ai-sdk/*`)

- **Tools:** `tool({ description, inputSchema, execute })` objects in the `tools` map of
  `generateText`/`streamText`, or on an agent class.
- **Gates:** a tool without `execute` returns the call to the app for a human decision. Recent
  versions also offer a per-tool approval flag; look for `needsApproval`.
- **Limits:** `stopWhen: stepCountIs(n)` (older code uses `maxSteps`).

## Raw Anthropic / OpenAI tool loops

- **Tools:** JSON schemas with `input_schema` (Anthropic) or `"type": "function"` (OpenAI), and
  the dispatcher that maps a tool name to a function. **Read the dispatcher**: that is where
  reach is decided.
- **Gates and limits:** only what the loop code implements. Look for a max-iterations counter.

## MCP servers

- **Client configs:** `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
  `claude_desktop_config.json`.
- **What the repo shows:** the command, the package and its pin, the env var names passed in, and
  remote URLs.
- **What the repo does not show:** the tool list and descriptions, which arrive at runtime, and
  the real scope of the tokens. List both under "Unverifiable statically" and name the server.
- **Servers defined in the repo** (`FastMCP`, `@mcp.tool`, `@modelcontextprotocol/sdk`): audit
  their tools like any other tool; any agent connected to them inherits their reach.
