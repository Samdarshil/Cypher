"""Local Ollama backend.

Deliberately implemented with stdlib `urllib` only, no extra dependency,
so CYPHER's core has zero required third-party packages for its most
important code path. Talks to a locally-running `ollama serve` instance.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .base import AIProvider, AIProviderError, GenerationResult


class OllamaProvider(AIProvider):
    name = "ollama"

    def __init__(
        self,
        model: str = "qwen3:4b",
        host: str = "http://localhost:11434",
        timeout_seconds: float = 120.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.host}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise AIProviderError(
                f"Could not reach Ollama at {self.host} — is `ollama serve` running? ({exc})"
            ) from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise AIProviderError(f"Ollama returned non-JSON response: {body[:200]!r}") from exc

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
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"

        result = self._post("/api/generate", payload)
        if "error" in result:
            raise AIProviderError(f"Ollama error: {result['error']}")

        text = result.get("response", "")
        latency = time.monotonic() - start
        return GenerationResult(
            text=text,
            model=self.model,
            latency_seconds=latency,
            prompt_tokens=result.get("prompt_eval_count"),
            completion_tokens=result.get("eval_count"),
            raw=result,
        )

    def health_check(self) -> tuple[bool, str]:
        try:
            result = self._post_get_tags()
        except AIProviderError as exc:
            return False, str(exc)
        models = [m.get("name") for m in result.get("models", [])]
        if self.model not in models and not any(m.startswith(self.model) for m in models if m):
            return False, f"Ollama reachable but model '{self.model}' not pulled. Available: {models}"
        return True, f"Ollama reachable, model '{self.model}' available."

    def _post_get_tags(self) -> dict:
        url = f"{self.host}/api/tags"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise AIProviderError(
                f"Could not reach Ollama at {self.host} — is `ollama serve` running? ({exc})"
            ) from exc
