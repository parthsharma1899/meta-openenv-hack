"""FastAPI server entry point for the Cybersecurity Intrusion Detection Environment."""

import sys
import os

# Ensure repo root is on the path so 'models' resolves correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI
from openenv.core.env_server import create_fastapi_app

from .environment import IDSEnvironment

# Import action/observation classes required by create_fastapi_app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import IDSAction, IDSObservation

app = create_fastapi_app(IDSEnvironment, IDSAction, IDSObservation)

# ---------------------------------------------------------------------------
# Extra endpoints required by the hackathon validator
# ---------------------------------------------------------------------------

_env_instance = IDSEnvironment()

TASKS_META = [
    {
        "id": "easy",
        "description": "Find all XFF threat signatures in a 90-char hex network traffic stream.",
        "difficulty": "easy",
        "max_steps": 1,
        "action_schema": {
            "action_type": "scan_traffic",
            "threat_positions": "List[int]",
        },
    },
    {
        "id": "medium",
        "description": "Create a 20-char detection rule near a suspicious anomaly and score accuracy.",
        "difficulty": "medium",
        "max_steps": 3,
        "action_schema": {
            "action_type": "create_detection_rule | evaluate_detection_accuracy",
            "position": "int (for create_detection_rule)",
            "rule": "str (for evaluate_detection_accuracy)",
        },
    },
    {
        "id": "hard",
        "description": "Assess false-positive rates for 3 candidate rules and recommend the safest.",
        "difficulty": "hard",
        "max_steps": 5,
        "action_schema": {
            "action_type": "evaluate_false_positives | select_optimal_rule",
            "rule_index": "int 0-2 (for evaluate_false_positives)",
            "ranking": "List[int] (for select_optimal_rule)",
            "selected_rule_index": "int (for select_optimal_rule)",
        },
    },
]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tasks")
def tasks():
    return {"tasks": TASKS_META}


@app.post("/grader")
def grader(payload: dict):
    """Grade a single action for a given task without a full episode."""
    task = payload.get("task", "easy")
    action_data = payload.get("action", {})

    env = IDSEnvironment()
    env.reset(task=task)
    action = IDSAction(**action_data)
    obs = env.step(action)

    raw_score = obs.reward or 0.0
    # Clamp to strict (0, 1) as required by validator
    if raw_score <= 0.0:
        score = 0.001
    elif raw_score >= 1.0:
        score = 0.999
    else:
        score = raw_score

    return {
        "task": task,
        "score": score,
        "reward": raw_score,
        "message": obs.message,
        "done": obs.done,
    }


def main() -> None:
    """Entry point for `uv run server`."""
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "7860")),
        reload=False,
    )


if __name__ == "__main__":
    main()
