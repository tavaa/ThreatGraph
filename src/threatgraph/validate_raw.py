"""Phase-1 validation of the raw data: existence, integrity, format, timestamps,
accessibility.

Two layers:
  * unit checks (``check_*``) take ONE file or ONE parsed document and return
    CheckResult objects -> easy to test with deliberately broken inputs
    (negative tests in notebook 01);
  * ``run_all`` applies them to the whole data/raw folder.

A phase is "valid" only if ``assert_all(results)`` passes. Phase 2 must not
start before that.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from .download import core_file_specs, nvd_dest
from .integrity import sha256_file
from .manifest import records_by_relpath, utc_now_iso

FAMILIES = ("existence", "integrity", "format", "timestamps", "accessibility")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass
class CheckResult:
    family: str
    name: str
    ok: bool
    detail: str = ""


def _r(family: str, name: str, ok: bool, detail: str = "") -> CheckResult:
    return CheckResult(family, name, bool(ok), detail)


# --------------------------------------------------------------------------- #
# Time helper
# --------------------------------------------------------------------------- #
_FRAC = re.compile(r"\.(\d+)")


def parse_iso(s: str) -> datetime:
    """Parse ISO-8601 timestamps seen in the sources: with 'Z', with 1-7
    fractional digits, or without timezone (NVD; interpreted as UTC)."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _FRAC.sub(lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_us_date(s: str) -> datetime:
    """PKEV metadata dates look like '07/28/2025' (MM/DD/YYYY)."""
    return datetime.strptime(s, "%m/%d/%Y").replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Unit checks -- existence / integrity / accessibility
# --------------------------------------------------------------------------- #
def check_file_exists(path: Path, label: str = "") -> CheckResult:
    p = Path(path)
    return _r("existence", f"exists {label or p.name}", p.is_file() and p.stat().st_size > 0,
              str(p) if not p.is_file() else f"{p.stat().st_size:,} B")


def check_file_integrity(path: Path, expected_sha256: str, expected_bytes: Optional[int] = None,
                         label: str = "") -> list[CheckResult]:
    p = Path(path)
    name = label or p.name
    if not p.is_file():
        return [_r("integrity", f"sha256 {name}", False, "file missing")]
    out = []
    if expected_bytes is not None:
        out.append(_r("integrity", f"size {name}", p.stat().st_size == expected_bytes,
                      f"expected {expected_bytes}, found {p.stat().st_size}"))
    got = sha256_file(p)
    out.append(_r("integrity", f"sha256 {name}", got == expected_sha256,
                  "match" if got == expected_sha256 else f"expected {expected_sha256[:16]}..., found {got[:16]}..."))
    return out


def check_file_accessible(path: Path, label: str = "") -> list[CheckResult]:
    p = Path(path)
    name = label or p.name
    out = [_r("accessibility", f"readable {name}", p.is_file() and os.access(p, os.R_OK))]
    if p.is_file():
        mode = p.stat().st_mode
        writable = bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        out.append(_r("accessibility", f"read-only mode {name}", not writable, oct(stat.S_IMODE(mode))))
    return out


# --------------------------------------------------------------------------- #
# Unit checks -- format (structure + expected counts)
# --------------------------------------------------------------------------- #
KEV_FIELDS = {
    "cveID": str, "vendorProject": str, "product": str, "vulnerabilityName": str, "dateAdded": str,
    "shortDescription": str, "requiredAction": str, "dueDate": str, "knownRansomwareCampaignUse": str,
    "notes": str, "cwes": list,
}


def check_kev_format(doc: dict, sources: dict) -> list[CheckResult]:
    exp = sources["expected_counts"]
    f = "format"
    out = [_r(f, "kev: top-level keys", {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"} <= set(doc),
              str(sorted(doc)))]
    vulns = doc.get("vulnerabilities", [])
    out.append(_r(f, "kev: entry count", len(vulns) == exp["kev_entries"], f"{len(vulns)} (expected {exp['kev_entries']})"))
    out.append(_r(f, "kev: 'count' field == len(vulnerabilities)", doc.get("count") == len(vulns), f"{doc.get('count')} vs {len(vulns)}"))
    bad_fields = [v.get("cveID") for v in vulns if set(v) != set(KEV_FIELDS)]
    out.append(_r(f, "kev: every entry has exactly the 11 expected fields", not bad_fields, f"{len(bad_fields)} bad"))
    bad_types = [v["cveID"] for v in vulns for k, t in KEV_FIELDS.items() if k in v and not isinstance(v[k], t)]
    out.append(_r(f, "kev: field types", not bad_types, f"{len(bad_types)} bad"))
    ids = [v.get("cveID", "") for v in vulns]
    out.append(_r(f, "kev: cveID pattern", all(CVE_RE.match(i) for i in ids)))
    out.append(_r(f, "kev: cveID unique", len(ids) == len(set(ids))))
    out.append(_r(f, "kev: dateAdded/dueDate are YYYY-MM-DD",
                  all(DATE_RE.match(v.get("dateAdded", "")) and DATE_RE.match(v.get("dueDate", "")) for v in vulns)))
    ransom = {v.get("knownRansomwareCampaignUse") for v in vulns}
    out.append(_r(f, "kev: ransomware flag in {Known, Unknown}", ransom <= {"Known", "Unknown"}, str(sorted(ransom))))
    return out


def check_pkev_format(doc: dict, sources: dict, kev_ids: Optional[set] = None,
                      technique_ids: Optional[set] = None) -> list[CheckResult]:
    exp = sources["expected_counts"]
    cv = sources["common_version"]
    f = "format"
    out = [_r(f, "pkev: top-level keys", {"metadata", "mapping_objects"} <= set(doc), str(sorted(doc)))]
    rows = doc.get("mapping_objects", [])
    md = doc.get("metadata", {})
    out.append(_r(f, "pkev: row count", len(rows) == exp["pkev_rows"], f"{len(rows)} (expected {exp['pkev_rows']})"))
    out.append(_r(f, "pkev: distinct CVEs", len({r.get("capability_id") for r in rows}) == exp["pkev_distinct_cves"],
                  f"{len({r.get('capability_id') for r in rows})}"))
    out.append(_r(f, "pkev: distinct techniques", len({r.get("attack_object_id") for r in rows}) == exp["pkev_distinct_techniques"],
                  f"{len({r.get('attack_object_id') for r in rows})}"))
    need = {"capability_id", "capability_description", "mapping_type", "attack_object_id", "attack_object_name",
            "capability_group", "references", "status", "mapping_framework_version"}
    out.append(_r(f, "pkev: required row keys", all(need <= set(r) for r in rows)))
    types = {r.get("mapping_type") for r in rows}
    out.append(_r(f, "pkev: mapping_type vocabulary", types <= {"exploitation_technique", "primary_impact", "secondary_impact"}, str(sorted(types))))
    out.append(_r(f, "pkev: attack_object_id pattern (T####[.###])", all(re.match(r"^T\d{4}(\.\d{3})?$", r.get("attack_object_id", "")) for r in rows)))
    out.append(_r(f, "pkev: metadata.attack_version", md.get("attack_version") == cv["attack_version"], str(md.get("attack_version"))))
    out.append(_r(f, "pkev: metadata.mapping_framework_version", md.get("mapping_framework_version") == cv["pkev_framework_version"],
                  str(md.get("mapping_framework_version"))))
    if kev_ids is not None:
        missing = {r["capability_id"] for r in rows} - kev_ids
        out.append(_r(f, "pkev x-ref: every CVE is in KEV", not missing, f"{len(missing)} not in KEV"))
    if technique_ids is not None:
        missing = {r["attack_object_id"] for r in rows} - technique_ids
        out.append(_r(f, "pkev x-ref: every technique id exists in ATT&CK 16.1", not missing, f"{len(missing)} unknown: {sorted(missing)[:5]}"))
    return out


def attack_technique_ids(doc: dict) -> set[str]:
    ids = set()
    for o in doc["objects"]:
        if o.get("type") == "attack-pattern":
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    ids.add(ref["external_id"])
    return ids


def check_attack_format(doc: dict, sources: dict) -> list[CheckResult]:
    exp = sources["expected_counts"]
    f = "format"
    objs = doc.get("objects", [])
    out = [
        _r(f, "attack: bundle type + spec_version", doc.get("type") == "bundle" and doc.get("spec_version") == "2.1",
           f"{doc.get('type')} / {doc.get('spec_version')}"),
        _r(f, "attack: object count", len(objs) == exp["attack_objects"], f"{len(objs)} (expected {exp['attack_objects']})"),
    ]
    n_ap = sum(o.get("type") == "attack-pattern" for o in objs)
    n_tac = sum(o.get("type") == "x-mitre-tactic" for o in objs)
    out.append(_r(f, "attack: attack-pattern count", n_ap == exp["attack_patterns"], f"{n_ap}"))
    out.append(_r(f, "attack: tactic count", n_tac == exp["attack_tactics"], f"{n_tac}"))
    out.append(_r(f, "attack: every object has id/type/spec_version-compatible shape",
                  all("id" in o and "type" in o and o["id"].startswith(o["type"] + "--") for o in objs)))
    out.append(_r(f, "attack: exactly one x-mitre-collection", sum(o.get("type") == "x-mitre-collection" for o in objs) == 1))
    return out


NVD_REQUIRED = {"id", "sourceIdentifier", "published", "lastModified", "vulnStatus", "descriptions"}


def check_nvd_record_format(rec: dict, cve_id: str) -> list[CheckResult]:
    return [
        _r("format", f"nvd {cve_id}: required keys", NVD_REQUIRED <= set(rec), str(sorted(NVD_REQUIRED - set(rec)))),
        _r("format", f"nvd {cve_id}: id == filename", rec.get("id") == cve_id, str(rec.get("id"))),
        _r("format", f"nvd {cve_id}: has a description", bool(rec.get("descriptions"))),
    ]


# --------------------------------------------------------------------------- #
# Unit checks -- timestamps
# --------------------------------------------------------------------------- #
def check_kev_timestamps(doc: dict, sources: dict) -> list[CheckResult]:
    cv = sources["common_version"]
    f = "timestamps"
    rel = parse_iso(doc["dateReleased"])
    added = [datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc) for v in doc["vulnerabilities"]]
    due = [datetime.strptime(v["dueDate"], "%Y-%m-%d").replace(tzinfo=timezone.utc) for v in doc["vulnerabilities"]]
    cutoff = parse_iso(cv["nvd_cutoff_utc"])
    return [
        _r(f, "kev: catalogVersion == common version", doc["catalogVersion"] == cv["kev_catalog_version"], doc["catalogVersion"]),
        _r(f, "kev: dateReleased falls on the common-version day", rel.strftime("%Y-%m-%d") == cv["label"], doc["dateReleased"]),
        _r(f, "kev: max(dateAdded) <= dateReleased", max(added) <= rel, max(added).strftime("%Y-%m-%d")),
        _r(f, "kev: dueDate < dateAdded only in the known anomalies",
           sum(a > d for a, d in zip(added, due)) == sources["known_anomalies"]["kev_due_before_added"],
           f"{sum(a > d for a, d in zip(added, due))} found, {sources['known_anomalies']['kev_due_before_added']} known"),
        _r(f, "kev: dateReleased not in the future", rel <= _now()),
    ]


def check_pkev_timestamps(doc: dict, sources: dict) -> list[CheckResult]:
    md = doc["metadata"]
    created, updated = parse_us_date(md["creation_date"]), parse_us_date(md["last_update"])
    return [
        _r("timestamps", "pkev: creation_date <= last_update", created <= updated, f"{md['creation_date']} <= {md['last_update']}"),
        _r("timestamps", "pkev: dates not in the future", updated <= _now()),
        _r("timestamps", "pkev: attack_version == common version", md["attack_version"] == sources["common_version"]["attack_version"]),
    ]


def check_attack_timestamps(doc: dict, sources: dict) -> list[CheckResult]:
    coll = [o for o in doc["objects"] if o.get("type") == "x-mitre-collection"][0]
    mods = [parse_iso(o["modified"]) for o in doc["objects"] if "modified" in o]
    created_after_modified = [o["id"] for o in doc["objects"] if "created" in o and "modified" in o
                              and parse_iso(o["created"]) > parse_iso(o["modified"])]
    return [
        _r("timestamps", "attack: collection x_mitre_version == common version",
           coll.get("x_mitre_version") == sources["common_version"]["attack_version"], str(coll.get("x_mitre_version"))),
        _r("timestamps", "attack: all 'modified' parse and are not in the future", bool(mods) and max(mods) <= _now(),
           f"max modified = {max(mods).isoformat()}"),
        _r("timestamps", "attack: created > modified only in the known anomalies",
           len(created_after_modified) == sources["known_anomalies"]["attack_created_after_modified"],
           f"{len(created_after_modified)} found, {sources['known_anomalies']['attack_created_after_modified']} known"),
    ]


def check_nvd_timestamps(rec: dict, cve_id: str, sources: dict) -> list[CheckResult]:
    cutoff = parse_iso(sources["common_version"]["nvd_cutoff_utc"])
    pub, mod = parse_iso(rec["published"]), parse_iso(rec["lastModified"])
    return [
        _r("timestamps", f"nvd {cve_id}: lastModified <= cutoff", mod <= cutoff, rec["lastModified"]),
        _r("timestamps", f"nvd {cve_id}: published <= lastModified", pub <= mod, f"{rec['published']} / {rec['lastModified']}"),
    ]


# --------------------------------------------------------------------------- #
# Whole-folder run
# --------------------------------------------------------------------------- #
def _load_json(path: Path, timings: dict, key: str) -> Any:
    t0 = time.perf_counter()
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    timings[key] = round(time.perf_counter() - t0, 3)
    return doc


def run_all(raw_dir: Path, sources: dict, manifest: dict) -> tuple[list[CheckResult], dict]:
    """Run every check on data/raw. Returns (results, stats)."""
    raw_dir = Path(raw_dir)
    res: list[CheckResult] = []
    stats: dict[str, Any] = {"parse_seconds": {}}
    recs = records_by_relpath(manifest)
    specs = core_file_specs(sources)

    # ---- existence ---------------------------------------------------------
    for sp in specs:
        res.append(check_file_exists(raw_dir / sp["relpath"], sp["relpath"]))
        res.append(_r("existence", f"in manifest {sp['relpath']}", sp["relpath"] in recs))
    kev_path = raw_dir / "kev" / "known_exploited_vulnerabilities.json"
    kev = _load_json(kev_path, stats["parse_seconds"], "kev")
    kev_ids = sorted(v["cveID"] for v in kev["vulnerabilities"])
    nvd_dir = raw_dir / sources["sources"]["nvd"]["dest_dir"] / sources["sources"]["nvd"]["per_cve"]["dest_subdir"]
    on_disk = sorted(p.stem for p in nvd_dir.glob("CVE-*.json"))
    res.append(_r("existence", "nvd: one file per KEV CVE (none missing)", not (set(kev_ids) - set(on_disk)),
                  f"missing: {sorted(set(kev_ids) - set(on_disk))[:5]}"))
    res.append(_r("existence", "nvd: no extra files", not (set(on_disk) - set(kev_ids)),
                  f"extra: {sorted(set(on_disk) - set(kev_ids))[:5]}"))
    res.append(_r("existence", "nvd: count == expected", len(on_disk) == sources["expected_counts"]["nvd_records"], str(len(on_disk))))
    res.append(_r("existence", "nvd: all NVD files listed in manifest",
                  all(nvd_dest(raw_dir, sources, c).relative_to(raw_dir).as_posix() in recs for c in kev_ids)))
    leftovers = list(raw_dir.rglob("*.part"))
    res.append(_r("existence", "no leftover *.part files", not leftovers, str(leftovers[:3])))

    # ---- integrity ---------------------------------------------------------
    for sp in specs:
        p = raw_dir / sp["relpath"]
        res += check_file_integrity(p, sp["sha256"], sp["bytes"], sp["relpath"])
        m = recs.get(sp["relpath"])
        if m:
            res.append(_r("integrity", f"manifest sha256 == registry {sp['relpath']}", m["sha256"] == sp["sha256"]))
    t0 = time.perf_counter()
    bad = []
    for c in kev_ids:
        p = nvd_dest(raw_dir, sources, c)
        m = recs.get(p.relative_to(raw_dir).as_posix())
        if not p.is_file() or m is None or sha256_file(p) != m["sha256"] or p.stat().st_size != m["bytes"]:
            bad.append(c)
    stats["nvd_hash_seconds"] = round(time.perf_counter() - t0, 2)
    res.append(_r("integrity", "nvd: all records match manifest sha256+size", not bad, f"{len(bad)} bad: {bad[:5]}"))
    per = sources["sources"]["nvd"]["per_cve"]
    canary = nvd_dest(raw_dir, sources, per["canary_cve"])
    res += check_file_integrity(canary, per["canary_sha256"], per["canary_bytes"], f"nvd canary {per['canary_cve']}")

    # ---- format ------------------------------------------------------------
    res += check_kev_format(kev, sources)
    pkev = _load_json(next(raw_dir.joinpath("pkev").glob("kev-*.json")), stats["parse_seconds"], "pkev")
    attack = _load_json(next(raw_dir.joinpath("attack").glob("enterprise-attack-*.json")), stats["parse_seconds"], "attack")
    res += check_attack_format(attack, sources)
    res += check_pkev_format(pkev, sources, set(kev_ids), attack_technique_ids(attack))
    nvd_docs: dict[str, dict] = {}
    t0 = time.perf_counter()
    for c in kev_ids:
        try:
            nvd_docs[c] = json.loads(nvd_dest(raw_dir, sources, c).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            res.append(_r("format", f"nvd {c}: valid JSON", False, str(exc)))
    stats["parse_seconds"]["nvd_all"] = round(time.perf_counter() - t0, 3)
    nvd_fmt = [x for c, d in nvd_docs.items() for x in check_nvd_record_format(d, c)]
    bad_fmt = [x for x in nvd_fmt if not x.ok]
    res.append(_r("format", f"nvd: {len(nvd_docs)} records parse and have required keys/id", not bad_fmt and len(nvd_docs) == len(kev_ids),
                  "; ".join(f"{x.name} ({x.detail})" for x in bad_fmt[:3])))

    # ---- timestamps --------------------------------------------------------
    res += check_kev_timestamps(kev, sources)
    res += check_pkev_timestamps(pkev, sources)
    res += check_attack_timestamps(attack, sources)
    nvd_ts = [x for c, d in nvd_docs.items() for x in check_nvd_timestamps(d, c, sources)]
    bad_ts = [x for x in nvd_ts if not x.ok]
    mods = [parse_iso(d["lastModified"]) for d in nvd_docs.values()]
    res.append(_r("timestamps", f"nvd: lastModified <= cutoff and published <= lastModified ({len(nvd_docs)} records)", not bad_ts,
                  "; ".join(f"{x.name}" for x in bad_ts[:3])))
    stats["nvd_max_lastModified"] = max(mods).isoformat() if mods else None
    now = _now()
    cutoff = parse_iso(sources["common_version"]["nvd_cutoff_utc"])
    m_times = [parse_iso(r["retrieved_at_utc"]) for r in manifest["files"]]
    res.append(_r("timestamps", "manifest: retrieved_at_utc within [cutoff, now]", all(cutoff <= t <= now for t in m_times),
                  f"{min(m_times).isoformat()} .. {max(m_times).isoformat()}"))
    res.append(_r("timestamps", "manifest: generated_at_utc not in the future", parse_iso(manifest["generated_at_utc"]) <= now))

    # ---- accessibility -----------------------------------------------------
    for sp in specs:
        res += check_file_accessible(raw_dir / sp["relpath"], sp["relpath"])
    unreadable = [c for c in kev_ids if not os.access(nvd_dest(raw_dir, sources, c), os.R_OK)]
    writable = [c for c in kev_ids if nvd_dest(raw_dir, sources, c).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)]
    res.append(_r("accessibility", "nvd: all records readable", not unreadable, f"{len(unreadable)} unreadable"))
    res.append(_r("accessibility", "nvd: all records read-only (mode bits)", not writable, f"{len(writable)} writable"))
    big = stats["parse_seconds"].get("attack", 0)
    res.append(_r("accessibility", "attack (46 MB) parses in < 30 s", big < 30, f"{big} s"))
    res.append(_r("accessibility", "raw_dir listable", os.access(raw_dir, os.R_OK | os.X_OK)))

    stats["nvd_records_parsed"] = len(nvd_docs)
    return res, stats


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def summarize(results: Iterable[CheckResult]) -> dict[str, dict[str, int]]:
    out = {f: {"passed": 0, "failed": 0} for f in FAMILIES}
    for r in results:
        out[r.family]["passed" if r.ok else "failed"] += 1
    return out


def assert_all(results: Iterable[CheckResult]) -> None:
    failed = [r for r in results if not r.ok]
    if failed:
        lines = "\n".join(f"  [{r.family}] {r.name}: {r.detail}" for r in failed)
        raise AssertionError(f"{len(failed)} validation check(s) failed:\n{lines}")


def write_report(path: Path, results: list[CheckResult], stats: dict, meta: dict) -> dict:
    doc = {
        "phase": 1,
        "generated_at_utc": utc_now_iso(),
        **meta,
        "summary": summarize(results),
        "all_passed": all(r.ok for r in results),
        "stats": stats,
        "checks": [asdict(r) for r in results],
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc
