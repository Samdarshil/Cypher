"""Central configuration. Everything here is overridable via environment
variables so the model/backend can change without touching code, per the
"model-agnostic architecture" requirement.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    ollama_host: str = os.environ.get("CYPHER_OLLAMA_HOST", "http://localhost:11434")
    ollama_model: str = os.environ.get("CYPHER_OLLAMA_MODEL", "qwen3:4b")
    workspaces_root: Path = Path(os.environ.get("CYPHER_WORKSPACES", "./workspaces"))
    max_iterations: int = int(os.environ.get("CYPHER_MAX_ITERATIONS", "15"))
    flag_format_regex: str = os.environ.get(
        "CYPHER_FLAG_REGEX", r"[A-Za-z0-9_]{3,20}\{[^{}\s]{1,200}\}"
    )
    provider: str = os.environ.get("CYPHER_PROVIDER", "ollama")  # "ollama" | "mock"
    use_docker_sandbox: bool = os.environ.get("CYPHER_USE_DOCKER", "0") == "1"
    docker_image: str = os.environ.get("CYPHER_DOCKER_IMAGE", "cypher-sandbox")
    sandbox_policy: str = os.environ.get("CYPHER_SANDBOX_POLICY", "competition")  # "competition" | "development"


SETTINGS = Settings()
