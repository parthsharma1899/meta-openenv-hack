"""FastAPI server entry point for the Cybersecurity Intrusion Detection Environment."""

import os

from openenv.core.env_server import create_fastapi_app

from .environment import IDSEnvironment

app = create_fastapi_app(IDSEnvironment)
