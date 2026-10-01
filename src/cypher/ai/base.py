"""AIProvider abstraction.

CYPHER must never be hard-coded to a single model/backend. Every reasoning
call in the investigation engine goes through this interface so the backend
(Ollama today, others later) can be swapped via configuration alone.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GenerationResult:
    """Structured result of a single AI generation call."""

    text: str
    model: str
    latency_seconds: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class AIProviderError(RuntimeError):
    """Raised when a provider fails to produce a usable response."""


class AIProvider(ABC):
    """Common interface every reasoning backend must implement.

    Implementations must be safe to call repeatedly in a loop: they should
    not raise on transient errors more than necessary, and should surface
    failures as AIProviderError so the investigation loop can degrade
    gracefully (retry, fall back, or escalate) instead of crashing.
    """

    name: str = "base"

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> GenerationResult:
        """Generate a completion.

        json_mode=True means the caller expects a single JSON object/array
        back with no surrounding prose. Providers that support a native
        structured-output mode should use it; others should instruct the
        model via the prompt and the caller should still validate/parse
        defensively (never trust raw model JSON blindly).
        """
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> tuple[bool, str]:
        """Return (ok, message) — used by `cypher doctor`."""
        raise NotImplementedError
