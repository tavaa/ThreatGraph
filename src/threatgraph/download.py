"""Phase 1 -- download the pinned raw files into data/raw/.

Design (see README "Phase 1"):
  * every URL is pinned to a git commit (no moving branch);
  * stream to "<file>.part", hash while streaming, then atomic rename:
    a crash can never leave a half-written file under the final name;
  * "Accept-Encoding: identity" so that Content-Length == bytes on disk and
    can be used as a first integrity check;
  * idempotent: a file that is already present and matches the expected hash
    is NOT downloaded again (status "cached");
  * retry with back-off on 429/5xx; one requests.Session per worker thread;
  * downloaded files are made read-only (raw data is immutable, OAIS-style).
"""
from __future__ import annotations

import json
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .integrity import IntegrityError, sha256_file
from .manifest import FileRecord, utc_now_iso

USER_AGENT = "threatgraph-ld/0.1 (university course project; polite client)"
TIMEOUT = (10, 60)  # (connect, read) seconds


# --------------------------------------------------------------------------- #
# HTTP session
# --------------------------------------------------------------------------- #
def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "identity"})
    return s


# --------------------------------------------------------------------------- #
# Registry helpers
# --------------------------------------------------------------------------- #
def core_file_specs(sources: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten sources.yaml into one list of file specs (excluding per-CVE NVD files)."""
    specs = []
    for sname, s in sources["sources"].items():
        for f in s["files"]:
            specs.append(
                {
                    "source": sname,
                    "role": f["role"],
                    "url": f"{s['raw_base']}/{f['path']}",
                    "relpath": f"{s['dest_dir']}/{Path(f['path']).name}",
                    "sha256": f["sha256"],
                    "bytes": f["bytes"],
                    "license": s.get("license"),
                    "pinned_ref": s["pinned_ref"],
                }
            )
    return specs


def nvd_relpath(cve_id: str) -> str:
    """CVE-2024-34102 -> CVE-2024/CVE-2024-341xx/CVE-2024-34102.json (mirror layout)."""
    _, year, num = cve_id.split("-")
    return f"CVE-{year}/CVE-{year}-{num[:-2]}xx/{cve_id}.json"


def nvd_url(sources: dict[str, Any], cve_id: str) -> str:
    return f"{sources['sources']['nvd']['raw_base']}/{nvd_relpath(cve_id)}"


def nvd_dest(raw_dir: Path, sources: dict[str, Any], cve_id: str) -> Path:
    s = sources["sources"]["nvd"]
    return raw_dir / s["dest_dir"] / s["per_cve"]["dest_subdir"] / f"{cve_id}.json"


# --------------------------------------------------------------------------- #
# Preflight (online accessibility)
# --------------------------------------------------------------------------- #
def head_check(session: requests.Session, url: str) -> dict[str, Any]:
    try:
        r = session.head(url, timeout=TIMEOUT, allow_redirects=True)
        return {"url": url, "status": r.status_code, "content_length": r.headers.get("Content-Length")}
    except requests.RequestException as exc:  # network problem, not an HTTP status
        return {"url": url, "status": None, "error": f"{type(exc).__name__}: {exc}"}


def preflight(sources: dict[str, Any], session: Optional[requests.Session] = None) -> list[dict[str, Any]]:
    """HEAD every core URL + the NVD canary. Cheap way to fail early."""
    session = session or make_session()
    urls = [(sp["relpath"], sp["url"]) for sp in core_file_specs(sources)]
    canary = sources["sources"]["nvd"]["per_cve"]["canary_cve"]
    urls.append((f"nvd/cve/{canary}.json (canary)", nvd_url(sources, canary)))
    out = []
    for label, url in urls:
        res = head_check(session, url)
        res["label"] = label
        out.append(res)
    return out


# --------------------------------------------------------------------------- #
# Single-file download
# --------------------------------------------------------------------------- #
def _make_read_only(path: Path) -> None:
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0o444


def _make_writable(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 0o644
    except FileNotFoundError:
        pass


def download_file(
    session: requests.Session,
    url: str,
    dest: Path,
    *,
    expected_sha256: Optional[str] = None,
    expected_bytes: Optional[int] = None,
) -> dict[str, Any]:
    """Download ``url`` to ``dest`` atomically. Returns a dict with bytes, sha256,
    http_status, etag. Raises IntegrityError on size/hash mismatch and
    requests.HTTPError on a non-2xx response. Nothing is left at ``dest`` on failure.
    """
    import hashlib

    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    h = hashlib.sha256()
    n = 0
    try:
        with session.get(url, stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()
            declared = r.headers.get("Content-Length")
            with open(part, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    if chunk:
                        fh.write(chunk)
                        h.update(chunk)
                        n += len(chunk)
            status, etag = r.status_code, r.headers.get("ETag")
        digest = h.hexdigest()
        if declared is not None and int(declared) != n:
            raise IntegrityError(f"truncated download: Content-Length={declared}, received={n} ({url})")
        if expected_bytes is not None and expected_bytes != n:
            raise IntegrityError(f"size mismatch: expected {expected_bytes}, got {n} ({url})")
        if expected_sha256 is not None and expected_sha256 != digest:
            raise IntegrityError(f"sha256 mismatch: expected {expected_sha256}, got {digest} ({url})")
        _make_writable(dest)          # needed on Windows if an old read-only copy exists
        os.replace(part, dest)        # atomic on the same filesystem
        _make_read_only(dest)
        return {"bytes": n, "sha256": digest, "http_status": status, "etag": etag}
    finally:
        if part.exists():
            part.unlink()


# --------------------------------------------------------------------------- #
# Core files (KEV, ATT&CK, PKEV, licenses, schemas)
# --------------------------------------------------------------------------- #
def download_core_files(
    sources: dict[str, Any],
    raw_dir: Path,
    session: Optional[requests.Session] = None,
    *,
    force: bool = False,
    previous: Optional[dict[str, dict]] = None,
    log: Callable[[str], None] = print,
) -> list[FileRecord]:
    """Download every non-per-CVE file. Cached if present AND hash matches the registry."""
    session = session or make_session()
    previous = previous or {}
    records: list[FileRecord] = []
    for sp in core_file_specs(sources):
        dest = raw_dir / sp["relpath"]
        status, info = "downloaded", None
        if dest.exists() and not force:
            try:
                if sha256_file(dest) == sp["sha256"]:
                    status = "cached"
            except OSError:
                pass
        if status == "cached":
            prev = previous.get(sp["relpath"])
            retrieved = prev["retrieved_at_utc"] if prev else _mtime_iso(dest)
            info = {"bytes": dest.stat().st_size, "sha256": sp["sha256"], "http_status": prev.get("http_status") if prev else None,
                    "etag": prev.get("etag") if prev else None}
        else:
            info = download_file(session, sp["url"], dest, expected_sha256=sp["sha256"], expected_bytes=sp["bytes"])
            retrieved = utc_now_iso()
        log(f"  [{status:10s}] {sp['relpath']:55s} {info['bytes']:>12,d} B")
        records.append(
            FileRecord(
                source=sp["source"], role=sp["role"], relpath=sp["relpath"], url=sp["url"],
                bytes=info["bytes"], sha256=info["sha256"], retrieved_at_utc=retrieved,
                http_status=info.get("http_status"), status=status, etag=info.get("etag"),
                license=sp["license"], pinned_ref=sp["pinned_ref"], expected_sha256=sp["sha256"],
            )
        )
    return records


def _mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# NVD: one JSON per KEV CVE
# --------------------------------------------------------------------------- #
def load_kev_cve_ids(kev_path: Path) -> list[str]:
    """The project scope: the CVE ids listed in the KEV catalog (sorted, unique)."""
    data = json.loads(Path(kev_path).read_text(encoding="utf-8"))
    ids = [v["cveID"] for v in data["vulnerabilities"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate cveID in KEV file")
    return sorted(ids)


_tls = threading.local()


def _thread_session() -> requests.Session:
    if not hasattr(_tls, "session"):
        _tls.session = make_session()
    return _tls.session


def _fetch_one_nvd(sources: dict[str, Any], raw_dir: Path, cve_id: str, force: bool,
                   previous: dict[str, dict]) -> FileRecord:
    s = sources["sources"]["nvd"]
    dest = nvd_dest(raw_dir, sources, cve_id)
    relpath = dest.relative_to(raw_dir).as_posix()
    url = nvd_url(sources, cve_id)
    prev = previous.get(relpath)
    # Cached only if the file is there AND matches the hash recorded earlier
    # (there is no registry hash per CVE; the manifest is the reference).
    if dest.exists() and not force and prev is not None:
        try:
            if sha256_file(dest) == prev["sha256"]:
                return FileRecord(
                    source="nvd", role="nvd_cve", relpath=relpath, url=url, bytes=dest.stat().st_size,
                    sha256=prev["sha256"], retrieved_at_utc=prev["retrieved_at_utc"],
                    http_status=prev.get("http_status"), status="cached", etag=prev.get("etag"),
                    license=s.get("license"), pinned_ref=s["pinned_ref"],
                )
        except OSError:
            pass
    exp = None
    if cve_id == s["per_cve"]["canary_cve"]:
        exp = (s["per_cve"]["canary_sha256"], s["per_cve"]["canary_bytes"])
    info = download_file(_thread_session(), url, dest,
                         expected_sha256=exp[0] if exp else None, expected_bytes=exp[1] if exp else None)
    return FileRecord(
        source="nvd", role="nvd_cve", relpath=relpath, url=url, bytes=info["bytes"], sha256=info["sha256"],
        retrieved_at_utc=utc_now_iso(), http_status=info["http_status"], status="downloaded",
        etag=info["etag"], license=s.get("license"), pinned_ref=s["pinned_ref"],
        expected_sha256=exp[0] if exp else None,
    )


def download_nvd_records(
    cve_ids: list[str],
    sources: dict[str, Any],
    raw_dir: Path,
    *,
    workers: int = 8,
    force: bool = False,
    previous: Optional[dict[str, dict]] = None,
    progress: bool = True,
) -> tuple[list[FileRecord], dict[str, str]]:
    """Download one NVD JSON per CVE id. Returns (records, errors{cve_id: message}).
    Errors are collected, not raised, so one bad record does not hide the others;
    the notebook then asserts ``errors == {}``.
    """
    previous = previous or {}
    records: list[FileRecord] = []
    errors: dict[str, str] = {}
    bar = None
    if progress:
        from tqdm.auto import tqdm
        bar = tqdm(total=len(cve_ids), desc="NVD records", unit="file")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_fetch_one_nvd, sources, raw_dir, c, force, previous): c for c in cve_ids}
        for fut in as_completed(futs):
            cve = futs[fut]
            try:
                records.append(fut.result())
            except Exception as exc:  # noqa: BLE001 - we want every failure reported
                errors[cve] = f"{type(exc).__name__}: {exc}"
            if bar:
                bar.update(1)
    if bar:
        bar.close()
    return sorted(records, key=lambda r: r.relpath), errors
