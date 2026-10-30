"""Small Python client for the ThreatGraph REST API (Phase 4).

    from threatgraph.api_client import ThreatGraphClient
    api = ThreatGraphClient("http://127.0.0.1:8000")
    for v in api.iter_vulnerabilities(technique="T1190", severity="CRITICAL"):
        print(v["cve_id"])
    doc = api.vulnerability("CVE-2024-34102", jsonld=True)       # JSON-LD document (dict)

Only needs ``requests``. It talks plain HTTP to a running server (python manage.py runserver), so it tests the
real network path: URL routing, content negotiation, status codes, pagination links.
"""
from __future__ import annotations

from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

JSON = "application/json"
JSONLD = "application/ld+json"


class ApiError(Exception):
    """HTTP status >= 400. ``status`` and ``body`` are kept for the caller (and for tests that expect an error)."""

    def __init__(self, status: int, url: str, body: Any):
        super().__init__(f"HTTP {status} for {url}: {str(body)[:200]}")
        self.status, self.url, self.body = status, url, body


class ThreatGraphClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 20.0, retries: int = 2,
                 session: requests.Session | None = None):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.s = session or requests.Session()
        # Retry only idempotent GETs on connection problems / 502-504 (never on 4xx: those are answers, not accidents)
        retry = Retry(total=retries, backoff_factor=0.3, status_forcelist=(502, 503, 504), allowed_methods=("GET",))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))

    # ------------------------------------------------------------------ low level
    def request(self, path: str, params: dict | None = None, accept: str = JSON, method: str = "GET") -> requests.Response:
        """Raw response (any status). ``path`` may be relative ('/api/...') or an absolute URL (the 'next' link)."""
        url = path if path.startswith("http") else self.base + path
        return self.s.request(method, url, params=params, headers={"Accept": accept}, timeout=self.timeout)

    def get(self, path: str, params: dict | None = None, accept: str = JSON) -> Any:
        """Parsed body; raises ApiError for status >= 400."""
        r = self.request(path, params, accept)
        body = r.json() if r.content else None
        if r.status_code >= 400:
            raise ApiError(r.status_code, r.url, body)
        return body

    # ------------------------------------------------------------------ resources
    def iter_pages(self, path: str, page_size: int = 200, **filters) -> Iterator[dict]:
        """Follow the ``next`` links until the last page. Yields whole pages (dict with count/next/results).
        Plain JSON only: the JSON-LD list has the same content under '@graph' (see the notebook)."""
        params: dict | None = {**{k: v for k, v in filters.items() if v is not None}, "page_size": page_size}
        url: str | None = path
        while url:
            page = self.get(url, params)
            yield page
            url, params = page.get("next"), None            # the 'next' link already contains the whole query

    def iter_vulnerabilities(self, page_size: int = 200, **filters) -> Iterator[dict]:
        for page in self.iter_pages("/api/vulnerabilities/", page_size, **filters):
            yield from page["results"]

    def iter_techniques(self, page_size: int = 200, **filters) -> Iterator[dict]:
        for page in self.iter_pages("/api/techniques/", page_size, **filters):
            yield from page["results"]

    def count(self, resource: str = "vulnerabilities", **filters) -> int:
        """Number of rows matching the filters (asks for a page of size 1: no need to download everything)."""
        return self.get(f"/api/{resource}/", {**filters, "page_size": 1})["count"]

    def vulnerability(self, cve_id: str, jsonld: bool = False) -> dict:
        return self.get(f"/api/vulnerabilities/{cve_id}/", accept=JSONLD if jsonld else JSON)

    def technique(self, technique_id: str, jsonld: bool = False) -> dict:
        return self.get(f"/api/techniques/{technique_id}/", accept=JSONLD if jsonld else JSON)

    def tactics(self) -> list[dict]:
        return self.get("/api/tactics/")

    def cwes(self, **filters) -> list[dict]:
        return [c for p in self.iter_pages("/api/cwes/", **filters) for c in p["results"]]

    def dataset(self) -> dict:
        """DCAT description of the whole dataset + provenance (JSON-LD)."""
        return self.get("/api/dataset/", accept=JSONLD)

    def context(self) -> dict:
        return self.get("/api/context/", accept=JSONLD)["@context"]
