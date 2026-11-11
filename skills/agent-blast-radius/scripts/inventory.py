#!/usr/bin/env python3
"""agent-blast-radius inventory: deterministic, read-only evidence sweep of an agent codebase.

Usage: python3 inventory.py [ROOT]   (prints JSON to stdout)

Never imports or executes target code. Never prints secret values: credentials are reported by
name and location only. Same repo in, same JSON out.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

VERSION = "0.2.0"

CODE_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".yaml", ".yml", ".sh"}
MCP_FILES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".nuxt",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", "vendor", "coverage",
    ".turbo", ".cache", "agent-blast-radius",
}
MAX_BYTES = 1_000_000
CAP_PER_RULE = 50
UNCAPPED = {"tool_definition", "mcp_server"}

# Dimensions reported in `absent` when nothing matched (framework/tool/mcp are context, not gaps;
# gate_bypass absent is good news).
DIMENSIONS = [
    "untrusted_input", "credential", "irreversible", "egress", "gate", "identity_audit", "recovery",
]

I = re.IGNORECASE

# (categories, rule, pattern). A rule may count toward several categories.
# ponytail: line-level regex, misses multi-line calls; the skill's read step covers that.
RULES: list[tuple[tuple[str, ...], str, re.Pattern[str]]] = [
    # frameworks
    (("framework",), "langgraph", re.compile(r"\blanggraph\b|@langchain/langgraph")),
    (("framework",), "langchain", re.compile(r"\bfrom langchain|\bimport langchain|@langchain/(?!langgraph)")),
    (("framework",), "deepagents", re.compile(r"\bdeepagents\b|create_deep_agent")),
    (("framework",), "crewai", re.compile(r"\bfrom crewai\b|\bimport crewai\b")),
    (("framework",), "openai_agents", re.compile(r"^\s*from agents(\.\w+)? import|@openai/agents")),
    (("framework",), "claude_agent_sdk", re.compile(r"claude_agent_sdk|@anthropic-ai/claude-agent-sdk")),
    (("framework",), "vercel_ai", re.compile(r"""from ['"]ai['"]|@ai-sdk/""")),
    (("framework",), "anthropic_sdk", re.compile(r"\bimport anthropic\b|\bfrom anthropic import|@anthropic-ai/sdk")),
    (("framework",), "openai_sdk", re.compile(r"""\bfrom openai import|\bimport openai\b|from ['"]openai['"]""")),
    (("framework",), "mcp_sdk", re.compile(r"\bFastMCP\b|@modelcontextprotocol/sdk|^\s*from mcp\b")),
    # tool definitions
    (("tool_definition",), "decorator_tool", re.compile(r"^\s*@tool\b")),
    (("tool_definition",), "decorator_function_tool", re.compile(r"^\s*@function_tool\b")),
    (("tool_definition",), "mcp_tool_decorator", re.compile(r"^\s*@\w+\.tool\b")),
    (("tool_definition",), "ts_tool_call", re.compile(r"\btool\(\s*\{")),
    (("tool_definition",), "tool_class", re.compile(r"\b(StructuredTool|BaseTool)\b")),
    (("tool_definition",), "raw_tool_schema", re.compile(r"""["']input_schema["']\s*:|["']type["']\s*:\s*["']function["']""")),
    # D1 untrusted input (reads that can carry attacker text)
    (("untrusted_input", "egress"), "http_read", re.compile(
        r"\brequests\.get\(|\bhttpx\.(get|stream)\(|\bfetch\(|\burlopen\(|\baxios\.get\(|\bWebBaseLoader\b")),
    (("untrusted_input",), "ticket_or_inbox", re.compile(
        r"zendesk|intercom|freshdesk|helpscout|helpdesk|\bjira\b|\bimaplib\b|gmail|\bget_issue|issues\.get\b|list_issues"
        r"|conversations_history|\.messages\.list\(", I)),
    (("untrusted_input",), "web_search", re.compile(r"tavily|duckduckgo|serpapi|brave_search|\bweb_search\b|google_search", I)),
    (("untrusted_input",), "document_loader", re.compile(r"\w+Loader\(|\bpypdf\b|\bunstructured\b|similarity_search|as_retriever\(")),
    (("untrusted_input", "egress"), "browser", re.compile(r"playwright|puppeteer|selenium|browser_use", I)),
    # D2/D3 credentials and reach (names only; values never emitted)
    (("credential",), "privileged_key", re.compile(r"service_role", I)),
    (("credential",), "cloud_metadata", re.compile(r"169\.254\.169\.254|metadata\.google\.internal")),
    # D4 irreversible
    (("irreversible",), "sql_execute", re.compile(r"\.(execute|executemany|executescript|exec_driver_sql)\(|\$executeRawUnsafe")),
    (("irreversible",), "sql_destructive", re.compile(r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+\w|DELETE\s+FROM|ALTER\s+TABLE)\b", I)),
    (("irreversible",), "shell_exec", re.compile(
        r"\bsubprocess\.|\bos\.system\(|\bos\.popen\(|child_process|\bexecSync\(|\bspawnSync\(|\bshell=True")),
    (("irreversible",), "code_eval", re.compile(
        r"(?<![.\w])(exec|eval)\(|allow_code_execution\s*=\s*True|allow_dangerous_code\s*=\s*True|PythonREPL|code_interpreter")),
    (("irreversible",), "unsafe_deserialization", re.compile(
        r"allow_dangerous_deserialization\s*=\s*True|\bpickle\.loads?\(|\btorch\.load\(|\byaml\.load\((?!.*SafeLoader)")),
    (("irreversible",), "file_delete", re.compile(
        r"shutil\.rmtree|\bos\.(remove|unlink|rmdir)\(|\brm\s+-rf\b|\bfs\.(rm|rmSync|unlink|unlinkSync)\(|\.unlink\(")),
    (("irreversible",), "infra_destroy", re.compile(
        r"terraform\W+destroy|kubectl\W+delete|helm\W+uninstall|aws\W+s3\W+rm|volumeDelete|delete_db_instance|DeleteDBInstance")),
    (("irreversible",), "deploy", re.compile(
        r"kubectl\W+apply|docker\W+push|vercel\W+deploy|fly\W+deploy|create_deployment|helm\W+(install|upgrade)")),
    (("irreversible",), "git_force", re.compile(r"push\W+(--force|-f)\b|reset\W+--hard")),
    (("irreversible",), "payment", re.compile(
        r"stripe\.(refunds|charges|transfers|payouts|paymentIntents|payment_intents)\.create"
        r"|stripe\.(Refund|Charge|Transfer|Payout|PaymentIntent)\.create"
        r"|\b(refunds|charges|transfers|payouts)\.create\("
        r"|\b(send|sign)_?[Tt]ransaction\b|\bwithdraw\w*\(|\btransfer_funds\b")),
    (("irreversible", "egress"), "email_send", re.compile(
        r"\bsmtplib\b|\.sendmail\(|\bsend_mail\(|sendgrid|resend\.emails|nodemailer|\.send_email\(|\bses\.send", I)),
    (("irreversible", "egress"), "messaging", re.compile(r"chat_postMessage|chat\.postMessage|webhook_url|WebhookClient|twilio", I)),
    # D5 egress
    (("egress",), "http_write", re.compile(
        r"\b(requests|httpx|axios|session|client)\.(post|put|patch)\(|method:\s*['\"](POST|PUT|PATCH|DELETE)['\"]")),
    (("egress",), "repo_write", re.compile(
        r"create_pull|create_issue|create_comment|create_file|update_file|pulls\.create|issues\.create|createPullRequest|git\W+push")),
    (("egress",), "upload", re.compile(r"put_object|upload_file|upload_fileobj|\.upload\(")),
    # D6 gates
    (("gate",), "human_approval", re.compile(
        r"(?<!auto-)(?<!auto_)\bapprov|\binterrupt\(|interrupt_(before|after|on)\b|HumanInTheLoop|human_in_the_loop"
        r"|needsApproval|needs_approval|human_input\s*=\s*True|can_use_tool", I)),
    (("gate",), "turn_limit", re.compile(
        r"recursion_limit|max_iter(ations)?\b|max_turns|maxTurns|maxSteps|max_steps|stopWhen|stepCountIs|max_execution_time|max_rpm")),
    (("gate",), "allowlist", re.compile(
        r"allow_?list|ALLOWED_[A-Z]+|allowed_(hosts|domains|tools|commands|urls)|allowedTools|deny_?list|block_?list|disallowed_tools", I)),
    (("gate",), "sandbox", re.compile(r"sandbox|\be2b\b|firecracker|gvisor|seccomp|--network[= ]none|read_only\s*=\s*True", I)),
    (("gate",), "dry_run", re.compile(r"dry_run|dryRun|--dry-run|terraform\W+plan")),
    (("gate",), "spend_cap", re.compile(r"max_budget|budget_usd|spend_limit|cost_limit|max_cost|token_budget|maxBudget")),
    (("gate_bypass",), "auto_approve", re.compile(
        r"auto[-_]approve|--yes\b|dangerously[-_]skip[-_]permissions|skip_permissions|bypassPermissions|--no-verify"
        r"|trust_remote_code\s*=\s*True", I)),
    # approvals that exist only as words to the model: not a gate
    (("prompt_only_gate",), "instruction_only", re.compile(
        r"\bonly (call|use) this (tool )?after\b|\b(call|use) this (tool )?only after\b|\bnever (call|send|run|use) \w+( \w+)? without\b"
        r"|\balways ask (the user )?(for )?(approval|confirmation)\b|\bmust be (approved|confirmed)\b", I)),
    # D7 identity and audit
    (("identity_audit",), "tracing", re.compile(
        r"opentelemetry|langfuse|langsmith|LANGCHAIN_TRACING|LANGSMITH_TRACING|@traceable|helicone|arize|phoenix|logfire|weave\.init|braintrust|agentops", I)),
    (("identity_audit",), "audit_log", re.compile(r"audit_?log|AuditLog|audit_event|log_tool_call|on_tool_start|on_tool_end", I)),
    (("identity_audit",), "kill_switch", re.compile(r"kill_?switch|emergency_stop|circuit_breaker", I)),
    # D8 boundary: anything that needs, or reaches, outside an air-gapped enclave
    (("boundary",), "hosted_model", re.compile(
        r"\b(ChatOpenAI|AzureChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|ChatVertexAI|ChatBedrock\w*|ChatMistralAI"
        r"|ChatGroq|ChatCohere|ChatFireworks|ChatTogether)\(|\b(Anthropic|AsyncAnthropic|OpenAI|AsyncOpenAI)\("
        r"|[\"'](anthropic|openai|google_genai|google_vertexai|bedrock\w*|mistralai|groq|cohere|fireworks|together):[\w.-]+[\"']"
        r"|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openai\.azure\.com"
        r"|\b(anthropic|openai|google|mistral|groq|cohere)\(\s*[\"']")),
    (("boundary",), "telemetry", re.compile(
        r"sentry_sdk\.init|Sentry\.init|posthog|mixpanel|segment\.(track|identify)|LANGCHAIN_TRACING_V2|LANGSMITH_TRACING"
        r"|smith\.langchain\.com|cloud\.langfuse\.com|\btelemetry\b", I)),
    (("boundary",), "runtime_fetch", re.compile(
        r"\bnpx\s+\S|\buvx\s+\S|\bpipx\s+run\b|\bpip3?\s+install\b|\bnpm\s+(install|i)\b|from_pretrained\("
        r"|hf_hub_download|snapshot_download|nltk\.download|spacy\.cli\.download|spacy\s+download|playwright\s+install"
        r"|tiktoken\.(get_encoding|encoding_for_model)|SentenceTransformer\(|urlretrieve\(")),
    (("boundary_control",), "offline_switch", re.compile(
        r"HF_HUB_OFFLINE|TRANSFORMERS_OFFLINE|DO_NOT_TRACK|ANONYMIZED_TELEMETRY|OTEL_SDK_DISABLED|CREWAI_DISABLE_TELEMETRY"
        r"|set_tracing_disabled|OPENAI_AGENTS_DISABLE_TRACING|local_files_only\s*=\s*True|\bbase_url\s*=|\bbaseURL\s*:"
        r"|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|\bollama\b|\bvllm\b|llama_cpp")),
    # detect & recover
    (("recovery",), "backup", re.compile(r"backup|snapshot|pg_dump|point_in_time|deletion_protection|prevent_destroy|\bPITR\b", I)),
]

# ponytail: ~1 s CPU per MB of source (measured: 14 MB in 18 s). Add literal prefilters if
# big monorepos matter; for now scan the agent subdirectory.
# Multiline so `^` anchors work in the whole-file prefilter as well as per line.
RULES = [(cats, rule, re.compile(p.pattern, p.flags | re.M)) for cats, rule, p in RULES]

ENV_READ = [
    re.compile(r"""os\.environ(?:\.get)?\s*[\[(]\s*['"]([A-Z][A-Z0-9_]*)['"]"""),
    re.compile(r"""os\.getenv\(\s*['"]([A-Z][A-Z0-9_]*)['"]"""),
    re.compile(r"""process\.env\.([A-Z][A-Z0-9_]*)"""),
    re.compile(r"""process\.env\[\s*['"]([A-Z][A-Z0-9_]*)['"]"""),
]
SECRET = re.compile(
    r"\b(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})"
)
CONN = re.compile(r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]+")
USERINFO = re.compile(r"://[^/@\s'\"]+@")
ENV_FILE_KEY = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=")
DOCKER_RUNTIME = re.compile(r"^\s*(CMD|ENTRYPOINT)\b", re.I)
URL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Hosts that stay inside an enclave, or are only namespace strings.
LOCAL_HOST = re.compile(
    r"^(localhost|.*\.(local|internal|localdomain|svc|cluster\.local|test|example|invalid)"
    r"|(.*\.)?example\.(com|org|net)|(.*\.)?w3\.org|json-schema\.org|schemas\..+|[\d.]+)$", re.I)


def redact(text: str) -> str:
    text = SECRET.sub("<redacted>", text)
    return USERINFO.sub("://<redacted>@", text)


# Credential rules emit a name instead of a snippet, so values never reach the output.
CRED_RULES = [("env_read", p, lambda m: m.group(1)) for p in ENV_READ] + [
    ("hardcoded_secret", SECRET, lambda m: f"hardcoded {m.group(1)[:4]}..."),
    ("connection_string", CONN,
     lambda m: f"{m.group(1)} URL" + (" with password" if USERINFO.search(m.group(0)) else "")),
]


def scan_code(rel: str, text: str, hits: list[dict], hosts: dict[str, dict], dockerfile: bool = False) -> None:
    lines = text.splitlines()
    for cats, rule, pat in RULES:
        if not pat.search(text):  # whole-file prefilter; most rules miss most files
            continue
        for n, line in enumerate(lines, 1):
            # Dockerfile RUN happens at build time, outside the enclave; CMD/ENTRYPOINT run inside it.
            if dockerfile and rule == "runtime_fetch" and not DOCKER_RUNTIME.match(line):
                continue
            if pat.search(line):
                snippet = redact(line.strip())[:160]
                for cat in cats:
                    hits.append({"category": cat, "rule": rule, "file": rel, "line": n, "snippet": snippet})
    for rule, pat, name_of in CRED_RULES:
        if not pat.search(text):
            continue
        for n, line in enumerate(lines, 1):
            for m in pat.finditer(line):
                hits.append({"category": "credential", "rule": rule, "file": rel, "line": n, "name": name_of(m)})
    if "://" in text:
        for n, line in enumerate(lines, 1):
            for m in URL_HOST.finditer(line):
                host = m.group(1).lower()
                if not LOCAL_HOST.match(host):
                    entry = hosts.setdefault(host, {"host": host, "count": 0, "first": f"{rel}:{n}"})
                    entry["count"] += 1


def scan_env(rel: str, text: str, hits: list[dict]) -> None:
    for n, line in enumerate(text.splitlines(), 1):
        m = ENV_FILE_KEY.match(line)
        if m:
            hits.append({"category": "credential", "rule": "env_file_key", "file": rel, "line": n, "name": m.group(1)})


RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "docker"}
FETCHERS = RUNNERS - {"docker"}  # resolve and download the package on start


def package_pinned(command: str, args: list[str]) -> tuple[str | None, bool | None]:
    if os.path.basename(command) not in RUNNERS:
        return None, None  # local script: nothing to pin
    positional = [a for a in args if not a.startswith("-") and a not in {"run", "exec", "dlx"}]
    if not positional:
        return None, None
    pkg = positional[0]
    if os.path.basename(command) == "docker":
        tag = pkg.rsplit("/", 1)[-1]
        return pkg, "@sha256:" in pkg or (":" in tag and not tag.endswith(":latest"))
    return pkg, pkg.rfind("@") > 0 or "==" in pkg


def scan_mcp(rel: str, text: str, hits: list[dict], unparsed: list[str]) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        unparsed.append(rel)
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        unparsed.append(rel)
        return
    lines = text.splitlines()
    for name in sorted(servers):
        cfg = servers[name] if isinstance(servers[name], dict) else {}
        args = [str(a) for a in cfg.get("args", [])]
        command = str(cfg.get("command", ""))
        pkg, pinned = package_pinned(command, args)
        url = str(cfg.get("url", ""))
        line = next((i for i, ln in enumerate(lines, 1) if f'"{name}"' in ln), 1)
        hits.append({
            "category": "mcp_server", "rule": "mcp_config", "file": rel, "line": line, "name": name,
            "command": os.path.basename(command) or None,
            "package": pkg,
            "pinned": pinned,
            "remote_host": re.sub(r"^\w+://([^/]+).*", r"\1", USERINFO.sub("://", url)) if url else None,
            "env_keys": sorted(cfg.get("env", {}) or {}),
            "credential_in_args": any(SECRET.search(a) or USERINFO.search(a) for a in args),
            "fetches_at_runtime": os.path.basename(command) in FETCHERS,
        })


def scan(root: str) -> dict:
    hits: list[dict] = []
    unparsed: list[str] = []
    hosts: dict[str, dict] = {}
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.exists(os.path.join(dirpath, d, "pyvenv.cfg"))
        )
        for fname in sorted(filenames):
            path = os.path.join(dirpath, fname)
            if os.path.islink(path) or os.path.getsize(path) > MAX_BYTES:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            is_env = fname == ".env" or fname.startswith(".env.")
            is_mcp = fname in MCP_FILES
            is_docker = fname.startswith("Dockerfile") or fname.endswith(".Dockerfile")
            is_code = os.path.splitext(fname)[1] in CODE_EXT or is_docker
            if not (is_env or is_mcp or is_code):
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            scanned += 1
            if is_env:
                scan_env(rel, text, hits)
            elif is_mcp:
                scan_mcp(rel, text, hits, unparsed)
            else:
                scan_code(rel, text, hits, hosts, dockerfile=is_docker)

    seen: set[str] = set()
    unique = []
    for h in sorted(hits, key=lambda h: (h["file"], h["line"], h["category"], h["rule"], h.get("name", ""))):
        key = json.dumps(h, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(h)
    # Cap each rule so a big repo stays readable. Files that define tools or MCP servers go first,
    # because that is where reach is decided. Tool and MCP hits are never capped.
    anchors = {h["file"] for h in unique if h["category"] in UNCAPPED}
    counts: dict[str, dict] = {}
    kept_per_rule: dict[str, int] = {}
    kept = []
    for h in sorted(unique, key=lambda h: (h["file"] not in anchors, h["file"], h["line"])):
        key = f'{h["category"]}/{h["rule"]}'
        c = counts.setdefault(key, {"hits": 0, "files": set()})
        c["hits"] += 1
        c["files"].add(h["file"])
        if h["category"] in UNCAPPED or kept_per_rule.get(key, 0) < CAP_PER_RULE:
            kept_per_rule[key] = kept_per_rule.get(key, 0) + 1
            kept.append(h)
    kept.sort(key=lambda h: (h["file"], h["line"], h["category"], h["rule"], h.get("name", "")))

    present = {h["category"] for h in unique}
    return {
        "tool": "agent-blast-radius inventory",
        "version": VERSION,
        "files_scanned": scanned,
        "frameworks": sorted({h["rule"] for h in unique if h["category"] == "framework"}),
        "absent": [d for d in DIMENSIONS if d not in present],
        "unparsed": unparsed,
        "counts": {k: {"hits": v["hits"], "files": len(v["files"])} for k, v in sorted(counts.items())},
        "truncated": sorted(k for k, v in counts.items() if k.split("/")[0] not in UNCAPPED and v["hits"] > CAP_PER_RULE),
        "external_hosts": [hosts[h] for h in sorted(hosts)][:100],
        "hits": kept,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?", default=".")
    root = ap.parse_args().root
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    json.dump(scan(root), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
