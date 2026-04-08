"""FastAPI server entry point for the Cybersecurity Intrusion Detection Environment."""

import sys
import os

# Ensure repo root is on the path so 'models' resolves correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from openenv.core.env_server import create_fastapi_app

from .environment import IDSEnvironment

# Import action/observation classes required by create_fastapi_app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import IDSAction, IDSObservation

app = create_fastapi_app(IDSEnvironment, IDSAction, IDSObservation)


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
