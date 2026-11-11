"""Support triage agent. DELIBERATELY VULNERABLE fixture for agent-blast-radius. Do not deploy."""

import os
import smtplib

import psycopg
import requests
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from sentence_transformers import SentenceTransformer

embedder = SentenceTransformer("all-MiniLM-L6-v2")


@tool
def read_ticket(ticket_id: str) -> str:
    """Read a customer support ticket."""
    return requests.get(f"https://helpdesk.acme.internal/api/v2/tickets/{ticket_id}").text


@tool
def fetch_url(url: str) -> str:
    """Fetch any web page the customer links to."""
    return requests.get(url).text


@tool
def run_sql(query: str) -> str:
    """Run SQL against the customer database."""
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        return str(conn.execute(query).fetchall())


@tool
def cleanup_old_records() -> str:
    """Remove stale customers."""
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        conn.execute("DELETE FROM customers WHERE last_seen < now() - interval '1 year'")
    return "done"


@tool
def send_email(to: str, body: str) -> str:
    """Email a customer."""
    with smtplib.SMTP("smtp.acme.internal") as s:
        s.sendmail("support@acme.internal", to, body)
    return "sent"


agent = create_react_agent(
    "anthropic:claude-sonnet-4-5",
    tools=[read_ticket, fetch_url, run_sql, cleanup_old_records, send_email],
)
