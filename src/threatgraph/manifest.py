"""Manifest = provenance record of every downloaded file.

One JSON file (data/raw/manifest.json) lists, for each file: where it came from
(url, pinned ref), when it was retrieved, how big it is, its SHA-256 and its
license. It is the Phase-1 "SIP receipt" (OAIS) and a minimal PROV-style
record (entity = file, activity = download, agent = this code).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class FileRecord:
    source: str                   # kev | nvd | attack | pkev
    role: str                     # data | schema | license | nvd_cve
    relpath: str                  # path relative to data/raw, posix style
    url: str
    bytes: int
    sha256: str
    retrieved_at_utc: str
    http_status: Optional[int] = None
    status: str = "downloaded"    # downloaded | cached
    etag: Optional[str] = None
    license: Optional[str] = None
    pinned_ref: Optional[str] = None
    expected_sha256: Optional[str] = None


def write_manifest(path: Path, records: Iterable[FileRecord], meta: dict) -> dict:
    records = sorted(records, key=lambda r: r.relpath)
    doc = {
        "manifest_version": 1,
        "generated_at_utc": utc_now_iso(),
        **meta,
        "file_count": len(records),
        "total_bytes": sum(r.bytes for r in records),
        "files": [asdict(r) for r in records],
    }
    tmp = Path(str(path) + ".part")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return doc


def read_manifest(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def records_by_relpath(manifest: dict) -> dict[str, dict]:
    return {f["relpath"]: f for f in manifest["files"]}
