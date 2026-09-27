"""RED AI Agent — Multi-agent SOC triage for Rule Evasion Detection alerts."""

import os

# Auto-load .env at import time
try:
    from dotenv import load_dotenv
    _env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    load_dotenv(_env, override=True)
except ImportError:
    pass

__all__ = ["llm", "schemas", "tools", "orchestrator"]
