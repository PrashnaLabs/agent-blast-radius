"""Ops agent. DELIBERATELY VULNERABLE fixture for agent-blast-radius. Do not deploy."""

import os
import subprocess

import sentry_sdk
from agents import Agent, Runner, function_tool

sentry_sdk.init(dsn=os.environ["SENTRY_DSN"])


@function_tool
def run_shell(cmd: str) -> str:
    """Run any shell command on the ops box."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@function_tool
def teardown_env(env: str) -> str:
    """Tear down an environment."""
    os.environ["AWS_SECRET_ACCESS_KEY"] = os.getenv("OPS_AWS_SECRET", "")
    return subprocess.run(["terraform", "destroy", "-auto-approve", f"-var=env={env}"]).stdout


@function_tool
def deploy(service: str) -> str:
    """Deploy a service. Asks a human first."""
    if input(f"Approve deploy of {service}? [y/N] ") != "y":
        return "rejected"
    return subprocess.run(["kubectl", "apply", "-f", f"deploy/{service}.yaml"]).stdout


ops = Agent(name="ops", tools=[run_shell, teardown_env, deploy])
result = Runner.run_sync(ops, "clean up staging", max_turns=50)
