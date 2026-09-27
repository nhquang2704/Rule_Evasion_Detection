"""Agent implementations — mỗi agent là 1 async function."""

from agent.agents.supervisor import run_supervisor
from agent.agents.triage import run_triage
from agent.agents.forensic import run_forensic
from agent.agents.hunt import run_hunt
from agent.agents.red_analyst import run_red_analyst
from agent.agents.mitre import run_mitre
from agent.agents.response import run_response
from agent.agents.report import run_report

__all__ = [
    "run_supervisor", "run_triage", "run_forensic",
    "run_hunt", "run_red_analyst", "run_mitre",
    "run_response", "run_report",
]
