"""
Every scenario module (app/scenarios/aXX_.../scenario.py) exposes a
module-level `SCENARIO` instance of this dataclass, including a real
FastAPI APIRouter with the actual vulnerable page(s)/endpoint(s).

Unlike the LLM playground, there's no model in the loop here — the
"exploit" is a real HTTP request against real (deliberately broken) app
logic, so flag capture happens inside each vulnerable route itself, by
calling capture_flag() the moment the vulnerable condition is actually
triggered.
"""

from dataclasses import dataclass
from fastapi import APIRouter


@dataclass
class Scenario:
    id: str                # e.g. "a05_injection"
    owasp_id: str          # e.g. "A05:2025"
    title: str             # e.g. "Injection"
    difficulty: str        # "Beginner" | "Intermediate" | "Advanced"
    tagline: str
    objective_md: str
    hints_md: str
    fix_md: str
    flag_id: str           # the exact flag string this scenario awards
    router: APIRouter      # mounted at /play/{id}/ by main.py
