"""Origin-restricted web fetching for authorized CTF web challenges.

The single most important property of this module: CYPHER can ONLY ever
fetch URLs on the same origin (scheme + hostname + port) as a URL the
human operator explicitly supplied. It can never be steered — by the LLM,
by challenge content, or by a redirect — into fetching an arbitrary
internet target. This is intentionally more restrictive than "the model
decides which URL to hit"; the model can only ask CYPHER to look at
different PATHS on the one authorized origin.

No subprocess is spawned here (stdlib `urllib` only), consistent with
"the executor is the only place a subprocess is spawned" — this is a
different, non-subprocess tool implementation, not an exception to that
rule.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

MAX_BODY_BYTES = 300_000
DEFAULT_TIMEOUT = 10.0
USER_AGENT = "CYPHER-CTF-Investigator/0.1 (authorized-target-only)"


class WebPolicyError(RuntimeError):
    """Raised whenever a fetch would leave the authorized origin(s)."""


@dataclass
class WebFetchResult:
    status: int
    headers: dict
    body: str
    truncated: bool
    final_url: str

    def to_text(self) -> str:
        header_lines = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        return (
            f"HTTP {self.status} {self.final_url}\n"
            f"--- headers ---\n{header_lines}\n"
            f"--- body ({'truncated' if self.truncated else 'full'}) ---\n{self.body}"
        )


def _origin(url: str) -> tuple[str, str, int]:
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise WebPolicyError(f"Refusing non-http(s) scheme: {url!r}")
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme, (p.hostname or "").lower(), port)


def is_same_origin(url: str, authorized_url: str) -> bool:
    try:
        return _origin(url) == _origin(authorized_url)
    except WebPolicyError:
        return False


def assert_authorized(url: str, authorized_urls: list[str]) -> None:
    if not authorized_urls:
        raise WebPolicyError("No authorized web target configured for this challenge.")
    if not any(is_same_origin(url, a) for a in authorized_urls):
        raise WebPolicyError(
            f"Refusing to fetch {url!r}: not on the same origin as any operator-authorized "
            f"target ({authorized_urls}). CYPHER never scans arbitrary internet hosts."
        )


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, authorized_urls: list[str]):
        super().__init__()
        self.authorized_urls = authorized_urls

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        assert_authorized(newurl, self.authorized_urls)  # raises WebPolicyError if not
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(
    url: str,
    authorized_urls: list[str],
    *,
    headers_only: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_BODY_BYTES,
) -> WebFetchResult:
    """Fetch a URL, enforcing the same-origin allowlist on both the initial
    request AND every redirect hop. Raises WebPolicyError rather than
    fetching anything out of scope.
    """
    assert_authorized(url, authorized_urls)

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if headers_only:
        req.get_method = lambda: "HEAD"

    opener = urllib.request.build_opener(_SameOriginRedirectHandler(authorized_urls))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = b"" if headers_only else resp.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            raw = raw[:max_bytes]
            return WebFetchResult(
                status=resp.status,
                headers=dict(resp.headers.items()),
                body=raw.decode("utf-8", errors="replace"),
                truncated=truncated,
                final_url=resp.geturl(),
            )
    except urllib.error.HTTPError as exc:
        # An HTTP error (404, 500, etc.) is still meaningful evidence for
        # a CTF web challenge -- return it rather than raising.
        body = exc.read(max_bytes) if not headers_only else b""
        return WebFetchResult(
            status=exc.code,
            headers=dict(exc.headers.items()) if exc.headers else {},
            body=body.decode("utf-8", errors="replace"),
            truncated=len(body) >= max_bytes,
            final_url=url,
        )


def derive_path(authorized_url: str, path: str) -> str:
    """Build a same-origin URL for a well-known path (robots.txt, etc.)
    from any URL on the authorized origin."""
    p = urllib.parse.urlparse(authorized_url)
    return urllib.parse.urlunparse((p.scheme, p.netloc, path, "", "", ""))
