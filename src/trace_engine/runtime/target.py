"""Target runtime specification."""

from urllib.parse import urlparse
from pydantic import BaseModel, Field


class Target(BaseModel):
    """Runtime target specification for security validation."""
    url: str
    scheme: str = "http"
    host: str = "127.0.0.1"
    port: int = 8000
    base_path: str = ""

    @classmethod
    def from_url(cls, url: str) -> "Target":
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if scheme == "https" else 80)
        base_path = parsed.path.rstrip("/")
        normalized_url = f"{scheme}://{host}:{port}{base_path}"
        return cls(url=normalized_url, scheme=scheme, host=host, port=port, base_path=base_path)
