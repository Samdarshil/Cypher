"""Deterministic mock provider — used for unit tests and CI where no local
model server is available. Never used as the default runtime provider.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Callable

from .base import AIProvider, GenerationResult


class MockProvider(AIProvider):
    """Returns pre-programmed or rule-based responses.

    Rules are checked FIRST (so a test can reliably intercept a specific
    call type — e.g. "always answer evidence-interpretation calls with
    this" — by matching on distinctive prompt text, regardless of how the
    queue is doing on unrelated calls). If no rule matches, the FIFO
    queue is used for sequential, ordered scripting of hypothesize/plan
    calls. If neither has anything, falls back to a harmless empty JSON
    object.
    """

    name = "mock"

    def __init__(self, responses: list[str] | None = None) -> None:
        self._queue: deque[str] = deque(responses or [])
        self._rules: list[tuple[Callable[[str], bool], Callable[[str], str]]] = []

    def add_rule(self, predicate: Callable[[str], bool], respond: Callable[[str], str]) -> None:
        self._rules.append((predicate, respond))

    def queue_response(self, text: str) -> None:
        self._queue.append(text)

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        json_mode: bool = False,
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> GenerationResult:
        start = time.monotonic()
        text = None
        for predicate, respond in self._rules:
            if predicate(prompt):
                text = respond(prompt)
                break
        if text is None:
            text = self._queue.popleft() if self._queue else "{}"
        return GenerationResult(
            text=text,
            model="mock-deterministic",
            latency_seconds=time.monotonic() - start,
        )

    def health_check(self) -> tuple[bool, str]:
        return True, "mock provider always healthy"
