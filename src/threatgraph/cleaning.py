"""Phase 2 -- raw (data/raw) -> clean (data/clean). Raw is only READ, never written.

Output = 10 relational tables as CSV (UTF-8, LF, deterministic order), one file per
table, plus data/clean/manifest.json (hash, row count, rule counters).
Every rule applied here corresponds to a numbered assumption in ASSUMPTIONS
(and in docs/phase2_cleaning_assumptions.md).

Layout decisions:
  * list-valued fields (KEV cwes, NVD weaknesses, PKEV references, ATT&CK
    kill-chain phases) become link tables  -> first normal form, maps to Django;
  * denormalised duplicates (PKEV technique name / CVE description) are dropped;
  * dates -> ISO-8601 (dates 'YYYY-MM-DD', timestamps UTC 'YYYY-MM-DDTHH:MM:SS.mmmZ');
  * NULL = "source did not provide it" (empty CSV cell); never imputed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from .integrity import IntegrityError, sha256_bytes, sha256_file
from .manifest import records_by_relpath, utc_now_iso

NONINFORMATIVE_CWE = {"NVD-CWE-noinfo", "NVD-CWE-Other"}

# --------------------------------------------------------------------------- #
# The assumptions (single source of truth; also printed by notebook 02)
# --------------------------------------------------------------------------- #
ASSUMPTIONS: dict[str, str] = {
    # general
    "G1": "Raw files are never modified. Cleaning starts only if every raw file still matches the Phase-1 manifest (SHA-256).",
    "G2": "Missing != empty. An empty/blank string becomes NULL (empty CSV cell). A missing list becomes zero rows in a link table. Nothing is imputed.",
    "G3": "No cross-source imputation: a value from source A never fills a gap in source B. Disagreements between sources are only reported (notebook 03).",
    "G4": "Text: leading/trailing whitespace is stripped; nothing else is changed (no case change, no translation, no unicode normalisation).",
    "G5": "Time: KEV dates are calendar dates (no zone). NVD timestamps have no zone and are ASSUMED to be UTC [UNCERTAIN]. ATT&CK timestamps are already UTC ('Z').",
    "G6": "Scope = the 1,391 CVEs in KEV. NVD/PKEV rows outside KEV would be an error (none exist). Unknown vocabulary values make cleaning fail loudly, not silently pass.",
    # KEV
    "K1": "knownRansomwareCampaignUse is kept as an enum {known, unknown}. 'unknown' means 'no evidence recorded', it is NOT 'false'.",
    "K2": "KEV 'cwes' = [] (CWE not provided) -> no rows in kev_cwe. Not filled from NVD.",
    "K3": "Entries with dueDate < dateAdded (15, bulk load 2021-11-03) keep their raw dates and get due_before_added = true. Not corrected.",
    # NVD
    "N1": "One row per CVE. description_en = the English description (NULL if none; none are missing).",
    "N2": "CVSS: only v3.1 goes into cvss_v31_*. Metric choice: the 'Primary' (NVD) metric if present, otherwise the first 'Secondary' (CNA); the type is stored. No v3.1 -> NULL. v2 score stored in its own column, never converted or mixed with v3.1.",
    "N3": "Weaknesses: one row per distinct (CVE, CWE, source). 'NVD-CWE-noinfo' and 'NVD-CWE-Other' are kept with is_informative = false (they say 'no usable CWE').",
    "N4": "vulnStatus is stored as given. 'Deferred' means NVD did not analyse the CVE: its scores can come only from the CNA ('Secondary').",
    "N5": "References are only counted (n_references); CPE configurations are not stored in this phase (out of scope, still in raw).",
    # ATT&CK
    "T1": "Only techniques (attack-pattern) and tactics (x-mitre-tactic) are kept. Malware, tools, groups, relationships, ... stay in raw (not needed for the KEV mapping).",
    "T2": "Revoked and deprecated techniques are kept with status = revoked|deprecated (history, possible references); consumers filter status = 'active'.",
    "T3": "parent_technique_id is derived from the id (T1059.001 -> T1059). The parent must exist in the table.",
    "T4": "Technique -> tactic comes from kill_chain_phases (kill_chain_name = 'mitre-attack', phase_name = tactic shortname). A technique may have several tactics.",
    # PKEV
    "P1": "One row per mapping object; mapping_id = 1-based position in the source file (stable for this pinned version).",
    "P2": "comments = null stays NULL (optional field).",
    "P3": "references are exploded to pkev_mapping_reference. The source field is dirty (glued URLs, fragments like 'Exploitation' or '[]'). A string made ONLY of whitespace/';'-separated http(s) URLs is split [INFERENCE]; any other string is kept verbatim and flagged is_http_url = false. Nothing is guessed or repaired. Repeats inside one mapping are dropped.",
    "P4": "capability_description and attack_object_name are dropped: they duplicate KEV and ATT&CK (update-anomaly risk). Differences are reported in notebook 03.",
    "P5": "PKEV covers only a subset of KEV. A CVE with no row = 'not mapped by PKEV', NOT 'no ATT&CK technique applies'.",
}


class CleanLog:
    """Counts how many times each rule fired (key = '<assumption id>.<what>')."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def hit(self, key: str, n: int = 1) -> None:
        if key.split(".")[0] not in ASSUMPTIONS:
            raise KeyError(f"unknown assumption id in log key {key!r}")
        if n:
            self.counts[key] = self.counts.get(key, 0) + n


# --------------------------------------------------------------------------- #
# Schema of the clean layer (single source of truth for writer, reader, validator)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Col:
    dtype: str                      # str | int | float | bool | date | datetime
    nullable: bool = False
    enum: Optional[frozenset] = None
    pattern: Optional[str] = None   # full-match regex (str columns)


@dataclass
class Table:
    columns: dict[str, Col]
    pk: list[str]
    fks: list[tuple[list[str], str, list[str]]] = field(default_factory=list)
    unique: list[list[str]] = field(default_factory=list)


CVE = r"CVE-\d{4}-\d{4,}"
CWE = r"CWE-\d+"
CWE_NVD = r"CWE-\d+|NVD-CWE-noinfo|NVD-CWE-Other"
TECH = r"T\d{4}(\.\d{3})?"
_URL = re.compile(r"https?://\S+")
VULN_STATUS = frozenset({"Received", "Awaiting Analysis", "Undergoing Analysis", "Analyzed", "Modified",
                         "Deferred", "Rejected", "Reanalysis"})  # [UNCERTAIN] completeness; 4 observed

SCHEMA: dict[str, Table] = {
    "kev_vulnerability": Table(
        {"cve_id": Col("str", pattern=CVE), "vendor_project": Col("str"), "product": Col("str"),
         "vulnerability_name": Col("str"), "date_added": Col("date"), "due_date": Col("date"),
         "short_description": Col("str"), "required_action": Col("str"),
         "ransomware_use": Col("str", enum=frozenset({"known", "unknown"})), "notes": Col("str"),
         "due_before_added": Col("bool"), "src_row": Col("int")},
        pk=["cve_id"]),
    "kev_cwe": Table(
        {"cve_id": Col("str", pattern=CVE), "cwe_id": Col("str", pattern=CWE)},
        pk=["cve_id", "cwe_id"], fks=[(["cve_id"], "kev_vulnerability", ["cve_id"])]),
    "nvd_cve": Table(
        {"cve_id": Col("str", pattern=CVE), "source_identifier": Col("str"), "published": Col("datetime"),
         "last_modified": Col("datetime"), "vuln_status": Col("str", enum=VULN_STATUS),
         "description_en": Col("str"),
         "cvss_v31_score": Col("float", nullable=True),
         "cvss_v31_severity": Col("str", nullable=True, enum=frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})),
         "cvss_v31_vector": Col("str", nullable=True, pattern=r"CVSS:3\.1/.+"),
         "cvss_v31_source": Col("str", nullable=True),
         "cvss_v31_type": Col("str", nullable=True, enum=frozenset({"Primary", "Secondary"})),
         "cvss_v2_score": Col("float", nullable=True), "n_references": Col("int")},
        pk=["cve_id"], fks=[(["cve_id"], "kev_vulnerability", ["cve_id"])]),
    "nvd_cve_cwe": Table(
        {"cve_id": Col("str", pattern=CVE), "cwe_id": Col("str", pattern=CWE_NVD), "source": Col("str"),
         "type": Col("str", enum=frozenset({"Primary", "Secondary"})), "is_informative": Col("bool")},
        pk=["cve_id", "cwe_id", "source"], fks=[(["cve_id"], "nvd_cve", ["cve_id"])]),
    "attack_tactic": Table(
        {"tactic_id": Col("str", pattern=r"TA\d{4}"), "shortname": Col("str"), "name": Col("str"), "stix_id": Col("str")},
        pk=["tactic_id"], unique=[["shortname"], ["stix_id"]]),
    "attack_technique": Table(
        {"technique_id": Col("str", pattern=TECH), "stix_id": Col("str"), "name": Col("str"),
         "is_subtechnique": Col("bool"), "parent_technique_id": Col("str", nullable=True, pattern=r"T\d{4}"),
         "status": Col("str", enum=frozenset({"active", "revoked", "deprecated"})),
         "created": Col("datetime"), "modified": Col("datetime"), "description": Col("str", nullable=True)},
        pk=["technique_id"], unique=[["stix_id"]],
        fks=[(["parent_technique_id"], "attack_technique", ["technique_id"])]),
    "attack_technique_tactic": Table(
        {"technique_id": Col("str", pattern=TECH), "tactic_id": Col("str", pattern=r"TA\d{4}")},
        pk=["technique_id", "tactic_id"],
        fks=[(["technique_id"], "attack_technique", ["technique_id"]), (["tactic_id"], "attack_tactic", ["tactic_id"])]),
    "pkev_mapping": Table(
        {"mapping_id": Col("int"), "cve_id": Col("str", pattern=CVE), "technique_id": Col("str", pattern=TECH),
         "mapping_type": Col("str", enum=frozenset({"exploitation_technique", "primary_impact", "secondary_impact"})),
         "capability_group": Col("str"), "comments": Col("str", nullable=True), "status": Col("str")},
        pk=["mapping_id"], unique=[["cve_id", "technique_id", "mapping_type"]],
        fks=[(["cve_id"], "kev_vulnerability", ["cve_id"]), (["technique_id"], "attack_technique", ["technique_id"])]),
    "pkev_mapping_reference": Table(
        {"mapping_id": Col("int"), "reference": Col("str"), "is_http_url": Col("bool")},
        pk=["mapping_id", "reference"], fks=[(["mapping_id"], "pkev_mapping", ["mapping_id"])]),
}


# --------------------------------------------------------------------------- #
# Raw loading (read-only)
# --------------------------------------------------------------------------- #
def verify_raw_inputs(raw_dir: Path, manifest: dict) -> int:
    """Assumption G1: every file listed in the Phase-1 manifest must still match its hash."""
    bad = []
    for f in manifest["files"]:
        p = Path(raw_dir) / f["relpath"]
        if not p.is_file() or p.stat().st_size != f["bytes"] or sha256_file(p) != f["sha256"]:
            bad.append(f["relpath"])
    if bad:
        raise IntegrityError(f"{len(bad)} raw file(s) differ from the Phase-1 manifest, e.g. {bad[:3]}")
    return len(manifest["files"])


def load_raw(raw_dir: Path) -> dict[str, Any]:
    raw_dir = Path(raw_dir)
    rd = lambda p: json.loads(p.read_text(encoding="utf-8"))  # noqa: E731
    nvd = {p.stem: rd(p) for p in sorted((raw_dir / "nvd" / "cve").glob("CVE-*.json"))}
    return {
        "kev": rd(raw_dir / "kev" / "known_exploited_vulnerabilities.json"),
        "pkev": rd(next((raw_dir / "pkev").glob("kev-*.json"))),
        "attack": rd(next((raw_dir / "attack").glob("enterprise-attack-*.json"))),
        "nvd": nvd,
    }


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _txt(x: Optional[str], log: CleanLog) -> Optional[str]:
    """G4 + G2: strip; blank -> None."""
    if x is None:
        return None
    if not isinstance(x, str):
        raise TypeError(f"expected str, got {type(x).__name__}")
    y = x.strip()
    if y != x:
        log.hit("G4.stripped_values")
    if y == "":
        log.hit("G2.blank_to_null")
        return None
    return y


def _ext_id(obj: dict) -> str:
    return next(r["external_id"] for r in obj.get("external_references", []) if r["source_name"] == "mitre-attack")


def _dates(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, format="%Y-%m-%d")


def _stamps(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, format="ISO8601", utc=True)


def _frame(rows: list[dict], table: str) -> pd.DataFrame:
    spec = SCHEMA[table]
    df = pd.DataFrame(rows, columns=list(spec.columns))
    for c, col in spec.columns.items():
        if col.dtype == "date":
            df[c] = _dates(df[c])
        elif col.dtype == "datetime":
            df[c] = _stamps(df[c])
        elif col.dtype == "int":
            df[c] = df[c].astype("Int64")
        elif col.dtype == "float":
            df[c] = df[c].astype("float64")
        elif col.dtype == "bool":
            df[c] = df[c].astype(bool)
        else:
            df[c] = df[c].astype("string")
    return df.sort_values(SCHEMA[table].pk, kind="stable").reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Per-source cleaning
# --------------------------------------------------------------------------- #
def clean_kev(doc: dict, log: CleanLog) -> dict[str, pd.DataFrame]:
    rows, cwes = [], set()
    for i, v in enumerate(doc["vulnerabilities"]):
        cve = _txt(v["cveID"], log)
        added, due = date.fromisoformat(v["dateAdded"]), date.fromisoformat(v["dueDate"])
        flag = due < added
        if flag:
            log.hit("K3.due_before_added")
        ransom = _txt(v["knownRansomwareCampaignUse"], log).lower()
        if ransom not in {"known", "unknown"}:
            raise ValueError(f"unexpected ransomware value {ransom!r} for {cve}")
        log.hit(f"K1.ransomware_{ransom}")
        if not v["cwes"]:
            log.hit("K2.empty_cwes")
        for c in v["cwes"]:
            cwes.add((cve, _txt(c, log)))
        rows.append({
            "cve_id": cve, "vendor_project": _txt(v["vendorProject"], log), "product": _txt(v["product"], log),
            "vulnerability_name": _txt(v["vulnerabilityName"], log), "date_added": v["dateAdded"], "due_date": v["dueDate"],
            "short_description": _txt(v["shortDescription"], log), "required_action": _txt(v["requiredAction"], log),
            "ransomware_use": ransom, "notes": _txt(v["notes"], log), "due_before_added": flag, "src_row": i})
    return {"kev_vulnerability": _frame(rows, "kev_vulnerability"),
            "kev_cwe": _frame([{"cve_id": a, "cwe_id": b} for a, b in sorted(cwes)], "kev_cwe")}


def _pick_metric(metrics: list[dict]) -> Optional[dict]:
    """N2: Primary first, else the first Secondary, else None."""
    prim = [m for m in metrics if m.get("type") == "Primary"]
    return prim[0] if prim else (metrics[0] if metrics else None)


def clean_nvd(records: dict[str, dict], log: CleanLog) -> dict[str, pd.DataFrame]:
    rows, weak = [], {}
    for cve, r in sorted(records.items()):
        en = [d["value"] for d in r["descriptions"] if d.get("lang") == "en"]
        if len(en) != 1:
            log.hit("N1.not_exactly_one_english_description")
        m31s = r["metrics"].get("cvssMetricV31", [])
        m31 = _pick_metric(m31s)
        if m31 is None:
            log.hit("N2.no_v31")
        else:
            if len(m31s) > 1:
                log.hit("N2.several_v31_metrics")
            if m31["type"] != "Primary":
                log.hit("N2.secondary_only")
        m2 = _pick_metric(r["metrics"].get("cvssMetricV2", []))
        if m31 is None and m2 is not None:
            log.hit("N2.v2_only")
        d31 = m31["cvssData"] if m31 else {}
        status = _txt(r["vulnStatus"], log)
        if status == "Deferred":
            log.hit("N4.deferred")
        for w in r.get("weaknesses", []):
            for d in w["description"]:
                cwe = _txt(d["value"], log)
                key = (cve, cwe, w["source"])
                if key in weak:
                    log.hit("N3.duplicate_rows_dropped")
                    continue
                inf = cwe not in NONINFORMATIVE_CWE
                if not inf:
                    log.hit("N3.noninformative")
                weak[key] = {"cve_id": cve, "cwe_id": cwe, "source": w["source"], "type": w["type"], "is_informative": inf}
        rows.append({
            "cve_id": cve, "source_identifier": _txt(r.get("sourceIdentifier"), log),
            "published": r["published"], "last_modified": r["lastModified"], "vuln_status": status,
            "description_en": _txt(en[0], log) if en else None,
            "cvss_v31_score": d31.get("baseScore"), "cvss_v31_severity": d31.get("baseSeverity"),
            "cvss_v31_vector": d31.get("vectorString"), "cvss_v31_source": m31["source"] if m31 else None,
            "cvss_v31_type": m31["type"] if m31 else None,
            "cvss_v2_score": m2["cvssData"]["baseScore"] if m2 else None,
            "n_references": len(r.get("references", []))})
    return {"nvd_cve": _frame(rows, "nvd_cve"), "nvd_cve_cwe": _frame(list(weak.values()), "nvd_cve_cwe")}


def clean_attack(doc: dict, log: CleanLog) -> dict[str, pd.DataFrame]:
    objs = doc["objects"]
    tactics = [o for o in objs if o["type"] == "x-mitre-tactic"]
    techs = [o for o in objs if o["type"] == "attack-pattern"]
    log.hit("T1.objects_not_kept", len(objs) - len(tactics) - len(techs))
    short2id = {o["x_mitre_shortname"]: _ext_id(o) for o in tactics}
    tac_rows = [{"tactic_id": _ext_id(o), "shortname": o["x_mitre_shortname"], "name": _txt(o["name"], log), "stix_id": o["id"]}
                for o in tactics]
    tech_rows, link = [], set()
    for o in techs:
        tid = _ext_id(o)
        if o.get("revoked") and o.get("x_mitre_deprecated"):
            raise ValueError(f"{tid} is both revoked and deprecated")
        status = "revoked" if o.get("revoked") else "deprecated" if o.get("x_mitre_deprecated") else "active"
        if status != "active":
            log.hit(f"T2.{status}")
        sub = "." in tid
        if sub:
            log.hit("T3.subtechniques")
        phases = [k["phase_name"] for k in o.get("kill_chain_phases", []) if k["kill_chain_name"] == "mitre-attack"]
        if not phases:
            log.hit("T4.technique_without_tactic")
        for ph in phases:
            link.add((tid, short2id[ph]))   # KeyError = unknown tactic -> fail loudly (G6)
        tech_rows.append({"technique_id": tid, "stix_id": o["id"], "name": _txt(o["name"], log), "is_subtechnique": sub,
                          "parent_technique_id": tid.split(".")[0] if sub else None, "status": status,
                          "created": o["created"], "modified": o["modified"], "description": _txt(o.get("description"), log)})
    return {"attack_tactic": _frame(tac_rows, "attack_tactic"), "attack_technique": _frame(tech_rows, "attack_technique"),
            "attack_technique_tactic": _frame([{"technique_id": a, "tactic_id": b} for a, b in sorted(link)], "attack_technique_tactic")}


def clean_pkev(doc: dict, log: CleanLog) -> dict[str, pd.DataFrame]:
    rows, refs = [], set()
    for i, r in enumerate(doc["mapping_objects"], start=1):
        comments = _txt(r.get("comments"), log)
        if comments is None:
            log.hit("P2.null_comments")
        rows.append({"mapping_id": i, "cve_id": _txt(r["capability_id"], log), "technique_id": _txt(r["attack_object_id"], log),
                     "mapping_type": _txt(r["mapping_type"], log), "capability_group": _txt(r["capability_group"], log),
                     "comments": comments, "status": _txt(r["status"], log)})
        seen = set()
        for raw_ref in r.get("references", []):
            ref = _txt(raw_ref, log)
            if ref is None:
                continue
            toks = [t.rstrip(";") for t in ref.split()]
            if len(toks) > 1 and all(_URL.fullmatch(t) for t in toks):
                items = toks                      # several real URLs glued together -> split
                log.hit("P3.multi_url_strings_split")
            else:
                items = [ref]                     # anything else is kept verbatim, never guessed
            for u in items:
                if u in seen:
                    log.hit("P3.duplicate_dropped")
                    continue
                seen.add(u)
                ok = bool(_URL.fullmatch(u))
                if not ok:
                    log.hit("P3.not_a_url")
                refs.add((i, u, ok))
    return {"pkev_mapping": _frame(rows, "pkev_mapping"),
            "pkev_mapping_reference": _frame([{"mapping_id": a, "reference": b, "is_http_url": c} for a, b, c in sorted(refs)],
                                             "pkev_mapping_reference")}


def clean_all(raw: dict[str, Any]) -> tuple[dict[str, pd.DataFrame], CleanLog]:
    log = CleanLog()
    tables: dict[str, pd.DataFrame] = {}
    for part in (clean_kev(raw["kev"], log), clean_nvd(raw["nvd"], log), clean_attack(raw["attack"], log), clean_pkev(raw["pkev"], log)):
        tables.update(part)
    return tables, log


# --------------------------------------------------------------------------- #
# Writing / reading the clean layer
# --------------------------------------------------------------------------- #
def _fmt(s: pd.Series, dtype: str) -> pd.Series:
    if dtype == "bool":
        return s.map({True: "true", False: "false"}).astype("string")
    if dtype == "date":
        return s.dt.strftime("%Y-%m-%d").astype("string")
    if dtype == "datetime":
        base = s.dt.strftime("%Y-%m-%dT%H:%M:%S.%f").astype("string")
        return base.str.slice(0, -3) + "Z"
    if dtype == "int":
        return s.astype("Int64").astype("string")
    if dtype == "float":
        return s.map(lambda v: None if pd.isna(v) else repr(float(v))).astype("string")
    return s.astype("string")


def serialize(df: pd.DataFrame, table: str) -> bytes:
    """Deterministic CSV bytes: schema column order, pk order, NULL = empty cell, UTF-8, LF."""
    spec = SCHEMA[table]
    out = pd.DataFrame({c: _fmt(df[c], col.dtype) for c, col in spec.columns.items()})
    out = out.sort_values(spec.pk, kind="stable").fillna("")
    return out.to_csv(index=False, lineterminator="\n").encode("utf-8")


def read_clean(table: str, clean_dir: Path) -> pd.DataFrame:
    spec = SCHEMA[table]
    df = pd.read_csv(Path(clean_dir) / f"{table}.csv", dtype="string", keep_default_na=False, na_values=[""])
    if list(df.columns) != list(spec.columns):
        raise ValueError(f"{table}: unexpected columns {list(df.columns)}")
    for c, col in spec.columns.items():
        if col.dtype == "bool":
            df[c] = df[c].map({"true": True, "false": False}).astype(bool)
        elif col.dtype == "int":
            df[c] = df[c].astype("Int64")
        elif col.dtype == "float":
            df[c] = df[c].astype("float64")
        elif col.dtype == "date":
            df[c] = _dates(df[c])
        elif col.dtype == "datetime":
            df[c] = _stamps(df[c])
    return df


def write_clean(tables: dict[str, pd.DataFrame], clean_dir: Path, log: CleanLog, meta: dict) -> dict:
    """Write the CSV files + manifest.json. Returns the manifest dict."""
    clean_dir = Path(clean_dir)
    clean_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in SCHEMA:
        data = serialize(tables[name], name)
        p = clean_dir / f"{name}.csv"
        tmp = p.with_name(p.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(p)
        files[name] = {"file": p.name, "rows": int(len(tables[name])), "columns": list(SCHEMA[name].columns),
                       "bytes": len(data), "sha256": sha256_bytes(data)}
    doc = {"phase": 2, "generated_at_utc": utc_now_iso(), **meta, "tables": files,
           "rule_counts": dict(sorted(log.counts.items())), "assumptions": sorted(ASSUMPTIONS)}
    tmp = clean_dir / "manifest.json.part"
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(clean_dir / "manifest.json")
    return doc