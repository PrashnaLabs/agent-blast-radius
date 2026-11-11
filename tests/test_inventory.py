import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCANNER = REPO / "skills" / "agent-blast-radius" / "scripts" / "inventory.py"
FIXTURE = REPO / "examples" / "vulnerable-agent"


def scan(root: Path) -> tuple[dict, str]:
    out = subprocess.run(
        [sys.executable, "-I", str(SCANNER), str(root)], capture_output=True, text=True, check=True
    ).stdout
    return json.loads(out), out


def hit_set(report: dict) -> set[tuple[str, str, str]]:
    return {(h["category"], h["rule"], h["file"]) for h in report["hits"]}


EXPECTED = {
    # support agent: untrusted ticket + web content, raw SQL, destructive SQL, email egress
    ("framework", "langchain", "agent.py"),
    ("framework", "langgraph", "agent.py"),
    ("tool_definition", "decorator_tool", "agent.py"),
    ("untrusted_input", "http_read", "agent.py"),
    ("egress", "http_read", "agent.py"),
    ("untrusted_input", "ticket_or_inbox", "agent.py"),
    ("credential", "env_read", "agent.py"),
    ("irreversible", "sql_execute", "agent.py"),
    ("irreversible", "sql_destructive", "agent.py"),
    ("egress", "email_send", "agent.py"),
    ("irreversible", "email_send", "agent.py"),
    ("boundary", "hosted_model", "agent.py"),
    ("boundary", "runtime_fetch", "agent.py"),
    # ops agent: shell, terraform destroy with auto-approve, gated deploy, turn limit, telemetry
    ("framework", "openai_agents", "ops_agent.py"),
    ("tool_definition", "decorator_function_tool", "ops_agent.py"),
    ("credential", "env_read", "ops_agent.py"),
    ("irreversible", "shell_exec", "ops_agent.py"),
    ("irreversible", "infra_destroy", "ops_agent.py"),
    ("irreversible", "deploy", "ops_agent.py"),
    ("gate_bypass", "auto_approve", "ops_agent.py"),
    ("gate", "human_approval", "ops_agent.py"),
    ("gate", "turn_limit", "ops_agent.py"),
    ("boundary", "telemetry", "ops_agent.py"),
    # billing assistant (TypeScript, Vercel AI SDK): web read + refunds
    ("framework", "vercel_ai", "web/agent.ts"),
    ("tool_definition", "ts_tool_call", "web/agent.ts"),
    ("untrusted_input", "http_read", "web/agent.ts"),
    ("egress", "http_read", "web/agent.ts"),
    ("credential", "env_read", "web/agent.ts"),
    ("irreversible", "payment", "web/agent.ts"),
    ("gate", "turn_limit", "web/agent.ts"),
    ("boundary", "hosted_model", "web/agent.ts"),
    # config and image
    ("credential", "env_file_key", ".env.example"),
    ("mcp_server", "mcp_config", ".mcp.json"),
    ("boundary", "runtime_fetch", "Dockerfile"),
}


def test_fixture_hits_exact():
    report, _ = scan(FIXTURE)
    got = hit_set(report)
    assert got - EXPECTED == set(), f"unexpected hits: {sorted(got - EXPECTED)}"
    assert EXPECTED - got == set(), f"missed hits: {sorted(EXPECTED - got)}"


def test_fixture_absences():
    report, _ = scan(FIXTURE)
    assert report["absent"] == ["identity_audit", "recovery"]


def test_auto_approve_is_not_a_gate():
    report, _ = scan(FIXTURE)
    src = (FIXTURE / "ops_agent.py").read_text().splitlines()
    approve_lines = [h["line"] for h in report["hits"] if h["rule"] == "human_approval"]
    assert [src[n - 1].strip()[:22] for n in approve_lines] == ['if input(f"Approve dep']


def test_credential_names_reported():
    report, _ = scan(FIXTURE)
    names = {h["name"] for h in report["hits"] if h["category"] == "credential"}
    assert names == {
        "DATABASE_URL", "AWS_SECRET_ACCESS_KEY", "OPS_AWS_SECRET", "PAYMENTS_SECRET_KEY", "ISSUES_TOKEN",
        "SENTRY_DSN",
    }


def test_mcp_servers_parsed():
    report, _ = scan(FIXTURE)
    servers = {h["name"]: h for h in report["hits"] if h["category"] == "mcp_server"}
    assert servers["issues"]["pinned"] is False
    assert servers["issues"]["env_keys"] == ["ISSUES_TOKEN"]
    assert servers["issues"]["fetches_at_runtime"] is True
    assert servers["postgres"]["pinned"] is True
    assert servers["postgres"]["credential_in_args"] is True


def test_secret_values_never_printed(tmp_path):
    (tmp_path / "bot.py").write_text(
        'from openai import OpenAI\n'
        'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        'DB = "postgresql://user:s3cretpw@db.internal/app"\n'
    )
    report, raw = scan(tmp_path)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in raw
    assert "s3cretpw" not in raw
    rules = {h["rule"] for h in report["hits"] if h["category"] == "credential"}
    assert rules == {"hardcoded_secret", "connection_string"}
    _, fixture_raw = scan(FIXTURE)
    assert "hunter2" not in fixture_raw


def test_vendor_dirs_skipped(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "index.js").write_text("require('child_process').execSync('rm -rf /')\n")
    report, _ = scan(tmp_path)
    assert report["hits"] == []
    assert report["files_scanned"] == 0


def test_cap_keeps_tool_files_first(tmp_path):
    (tmp_path / "a_noise.py").write_text("import subprocess\n" + "subprocess.run(['ls'])\n" * 60)
    (tmp_path / "z_tools.py").write_text("@tool\ndef sh(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    report, _ = scan(tmp_path)
    shell = [h for h in report["hits"] if h["rule"] == "shell_exec"]
    assert len(shell) == 50
    assert ("z_tools.py", 3) in {(h["file"], h["line"]) for h in shell}
    assert report["counts"]["irreversible/shell_exec"] == {"hits": 61, "files": 2}
    assert report["truncated"] == ["irreversible/shell_exec"]


def test_build_time_install_is_not_flagged_but_runtime_is():
    report, _ = scan(FIXTURE)
    lines = [h["line"] for h in report["hits"] if h["file"] == "Dockerfile"]
    assert lines == [6]  # CMD pip install; the RUN at line 4 happens at build time


def test_external_hosts_summary(tmp_path):
    (tmp_path / "a.py").write_text(
        'URL = "https://telemetry.vendor-x.io/collect"\n'
        'LOCAL = "http://localhost:8000/v1"\n'
        'INTERNAL = "https://api.corp.internal/x"\n'
        'OTHER = "https://telemetry.vendor-x.io/v2"\n'
    )
    report, _ = scan(tmp_path)
    assert report["external_hosts"] == [
        {"host": "telemetry.vendor-x.io", "count": 2, "first": "a.py:1"},
    ]


def test_deterministic():
    assert scan(FIXTURE)[1] == scan(FIXTURE)[1]
