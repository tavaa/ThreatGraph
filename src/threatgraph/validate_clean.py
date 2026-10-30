"""Phase-2 gate: are the CLEAN tables consistent enough to build the database?

Check families:
  schema     columns, dtypes, NULLs only where allowed, no blank / padded strings
  keys       primary keys, unique constraints, foreign keys (referential integrity)
  domain     enums, regex patterns, numeric ranges, date bounds
  semantic   rules that link several columns (score <-> severity, flags <-> dates, ...)
  reconcile  row/NULL counts equal an INDEPENDENT recount straight from the raw JSON
  provenance clean files == clean manifest (sha256, round trip), raw files untouched

Unit checks take DataFrames, so the negative tests in notebook 03 can feed broken ones.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd
from pandas.api import types as pdt

from . import cleaning as C
from .integrity import sha256_bytes, sha256_file
from .validate_raw import CheckResult, parse_iso

FAMILIES = ("schema", "keys", "domain", "semantic", "reconcile", "provenance")


def _r(f: str, name: str, ok: bool, detail: str = "") -> CheckResult:
    return CheckResult(f, name, bool(ok), detail)


def summarize(results) -> dict[str, dict[str, int]]:
    out = {f: {"passed": 0, "failed": 0} for f in FAMILIES}
    for r in results:
        out[r.family]["passed" if r.ok else "failed"] += 1
    return out


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
def _dtype_ok(s: pd.Series, dtype: str) -> bool:
    if dtype == "str":
        return pdt.is_string_dtype(s) or pdt.is_object_dtype(s)
    if dtype == "int":
        return pdt.is_integer_dtype(s)
    if dtype == "float":
        return pdt.is_float_dtype(s)
    if dtype == "bool":
        return pdt.is_bool_dtype(s)
    if dtype == "date":
        return pdt.is_datetime64_any_dtype(s) and getattr(s.dtype, "tz", None) is None
    if dtype == "datetime":
        return pdt.is_datetime64_any_dtype(s) and getattr(s.dtype, "tz", None) is not None
    return False


def check_schema(tables: dict[str, pd.DataFrame]) -> list[CheckResult]:
    out = []
    for name, spec in C.SCHEMA.items():
        if name not in tables:
            out.append(_r("schema", f"{name}: table present", False))
            continue
        df = tables[name]
        out.append(_r("schema", f"{name}: columns == schema (names and order)", list(df.columns) == list(spec.columns),
                      str(list(df.columns))))
        out.append(_r("schema", f"{name}: not empty", len(df) > 0, f"{len(df)} rows"))
        bad_t, bad_n, bad_b, bad_w = [], [], [], []
        for c, col in spec.columns.items():
            if c not in df:
                continue
            s = df[c]
            if not _dtype_ok(s, col.dtype):
                bad_t.append(f"{c}:{s.dtype}")
            if not col.nullable and s.isna().any():
                bad_n.append(f"{c}:{int(s.isna().sum())}")
            if col.dtype == "str":
                v = s.dropna().astype(str)
                bad_b += [f"{c}:blank" for _ in [0] if (v.str.strip() == "").any()]
                bad_w += [f"{c}:padded" for _ in [0] if (v != v.str.strip()).any()]
        out.append(_r("schema", f"{name}: dtypes", not bad_t, ", ".join(bad_t)))
        out.append(_r("schema", f"{name}: NULL only in nullable columns", not bad_n, ", ".join(bad_n)))
        out.append(_r("schema", f"{name}: no blank strings, no edge whitespace", not bad_b and not bad_w, ", ".join(bad_b + bad_w)))
    return out


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #
def check_keys(tables: dict[str, pd.DataFrame]) -> list[CheckResult]:
    out = []
    for name, spec in C.SCHEMA.items():
        df = tables[name]
        out.append(_r("keys", f"{name}: primary key {spec.pk} unique", not df.duplicated(spec.pk).any(),
                      f"{int(df.duplicated(spec.pk).sum())} duplicates"))
        for u in spec.unique:
            d = df.dropna(subset=u).duplicated(u)
            out.append(_r("keys", f"{name}: unique {u}", not d.any(), f"{int(d.sum())} duplicates"))
        for cols, ref, refcols in spec.fks:
            child = df[cols].dropna().drop_duplicates()
            parent = tables[ref][refcols].drop_duplicates()
            parent.columns, child.columns = cols, cols
            miss = child.merge(parent, how="left", on=cols, indicator=True).query("_merge == 'left_only'")
            out.append(_r("keys", f"{name}{cols} -> {ref}{refcols}", miss.empty, f"{len(miss)} orphans: {miss[cols[0]].head(3).tolist()}"))
    return out


# --------------------------------------------------------------------------- #
# domain
# --------------------------------------------------------------------------- #
def check_domain(tables: dict[str, pd.DataFrame], sources: dict) -> list[CheckResult]:
    out = []
    for name, spec in C.SCHEMA.items():
        df = tables[name]
        for c, col in spec.columns.items():
            s = df[c].dropna()
            if col.enum is not None:
                bad = set(s.astype(str)) - col.enum
                out.append(_r("domain", f"{name}.{c} in enum", not bad, f"unexpected: {sorted(bad)[:5]}"))
            if col.pattern is not None:
                bad = ~s.astype(str).str.fullmatch(col.pattern)
                out.append(_r("domain", f"{name}.{c} matches {col.pattern}", not bad.any(), f"{int(bad.sum())} bad, e.g. {s[bad].head(2).tolist()}"))
    nvd, kev, att = tables["nvd_cve"], tables["kev_vulnerability"], tables["attack_technique"]
    for c in ("cvss_v31_score", "cvss_v2_score"):
        s = nvd[c].dropna()
        out.append(_r("domain", f"nvd_cve.{c} within [0, 10]", s.between(0, 10).all()))
    out.append(_r("domain", "nvd_cve.n_references >= 0", (nvd.n_references >= 0).all()))
    cutoff = parse_iso(sources["common_version"]["nvd_cutoff_utc"])
    out.append(_r("domain", "nvd_cve.last_modified <= cutoff", (nvd.last_modified <= cutoff).all(), str(nvd.last_modified.max())))
    out.append(_r("domain", "nvd_cve.published <= last_modified", (nvd.published <= nvd.last_modified).all()))
    out.append(_r("domain", "kev.date_added <= snapshot day", (kev.date_added <= pd.Timestamp(sources["common_version"]["label"])).all(),
                  str(kev.date_added.max().date())))
    out.append(_r("domain", "attack_technique.created <= modified", (att.created <= att.modified).all()))
    return out


# --------------------------------------------------------------------------- #
# semantic
# --------------------------------------------------------------------------- #
def _band(score: float) -> str:
    return "NONE" if score == 0 else "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def check_semantic(tables: dict[str, pd.DataFrame]) -> list[CheckResult]:
    kev, nvd, cw = tables["kev_vulnerability"], tables["nvd_cve"], tables["nvd_cve_cwe"]
    att, tt, pk = tables["attack_technique"], tables["attack_technique_tactic"], tables["pkev_mapping"]
    out = []
    v = nvd.dropna(subset=["cvss_v31_score"])
    out.append(_r("semantic", "nvd: severity matches CVSS v3.1 score band", (v.cvss_v31_score.map(_band) == v.cvss_v31_severity).all()))
    cols = ["cvss_v31_score", "cvss_v31_severity", "cvss_v31_vector", "cvss_v31_source", "cvss_v31_type"]
    n = nvd[cols].isna().sum(axis=1)
    out.append(_r("semantic", "nvd: the 5 cvss_v31_* columns are all NULL or all filled", n.isin([0, 5]).all()))
    out.append(_r("semantic", "kev: due_before_added == (due_date < date_added)", (kev.due_before_added == (kev.due_date < kev.date_added)).all()))
    out.append(_r("semantic", "attack: is_subtechnique == ('.' in id)", (att.is_subtechnique == att.technique_id.str.contains(".", regex=False)).all()))
    sub = att[att.is_subtechnique]
    out.append(_r("semantic", "attack: parent_technique_id == id prefix, NULL for techniques",
                  (sub.parent_technique_id == sub.technique_id.str.split(".").str[0]).all() and att[~att.is_subtechnique].parent_technique_id.isna().all()))
    out.append(_r("semantic", "attack: every technique has >= 1 tactic", set(att.technique_id) <= set(tt.technique_id)))
    inf = cw.cwe_id.isin(C.NONINFORMATIVE_CWE)
    out.append(_r("semantic", "nvd_cve_cwe: is_informative == (cwe not NVD-CWE-noinfo/Other)", (cw.is_informative == ~inf).all()))
    act = att.set_index("technique_id").status
    out.append(_r("semantic", "pkev: every mapped technique is 'active' in ATT&CK 16.1", (pk.technique_id.map(act) == "active").all(),
                  str(pk.technique_id.map(act).value_counts().to_dict())))
    return out


# --------------------------------------------------------------------------- #
# reconcile: independent recount from raw (different code path on purpose)
# --------------------------------------------------------------------------- #
def _ref_items(r: dict) -> set[str]:
    """Independent re-implementation of the P3 rule (startswith instead of regex)."""
    items: set[str] = set()
    for ref in r.get("references", []):
        ref = (ref or "").strip()
        if not ref:
            continue
        toks = [t.rstrip(";") for t in ref.split()]
        if len(toks) > 1 and all(t.startswith(("http://", "https://")) for t in toks):
            items |= set(toks)
        else:
            items.add(ref)
    return items


def expected_from_raw(raw: dict[str, Any]) -> dict[str, Any]:
    kev, pk, att, nvd = raw["kev"]["vulnerabilities"], raw["pkev"]["mapping_objects"], raw["attack"]["objects"], raw["nvd"]
    tech = [o for o in att if o["type"] == "attack-pattern"]
    mitre = lambda o: [k["phase_name"] for k in o.get("kill_chain_phases", []) if k["kill_chain_name"] == "mitre-attack"]  # noqa: E731
    weak = lambda r: {(w["source"], d["value"].strip()) for w in r["weaknesses"] for d in w["description"]}  # noqa: E731
    rows = {
        "kev_vulnerability": len(kev),
        "kev_cwe": sum(len({c.strip() for c in v["cwes"]}) for v in kev),
        "nvd_cve": len(nvd),
        "nvd_cve_cwe": sum(len(weak(r)) for r in nvd.values()),
        "attack_tactic": sum(o["type"] == "x-mitre-tactic" for o in att),
        "attack_technique": len(tech),
        "attack_technique_tactic": sum(len(set(mitre(o))) for o in tech),
        "pkev_mapping": len(pk),
        "pkev_mapping_reference": sum(len(_ref_items(r)) for r in pk),
    }
    nulls = {
        "nvd_cve.cvss_v31_score": sum(not r["metrics"].get("cvssMetricV31") for r in nvd.values()),
        "nvd_cve.cvss_v31_type=Secondary": sum(bool(r["metrics"].get("cvssMetricV31")) and
                                               not any(m["type"] == "Primary" for m in r["metrics"]["cvssMetricV31"]) for r in nvd.values()),
        "nvd_cve.cvss_v2_score": sum(not r["metrics"].get("cvssMetricV2") for r in nvd.values()),
        "pkev_mapping.comments": sum(not (r.get("comments") or "").strip() for r in pk),
        "kev.due_before_added": sum(v["dueDate"] < v["dateAdded"] for v in kev),
        "kev.no_cwes": sum(not v["cwes"] for v in kev),
        "nvd_cve_cwe.noninformative": sum(1 for r in nvd.values() for s, c in weak(r) if c in C.NONINFORMATIVE_CWE),
        "pkev_mapping_reference.not_http_url": sum(1 for r in pk for u in _ref_items(r)
                                                   if not (u.startswith(("http://", "https://")) and len(u.split()) == 1)),
        "attack_technique.status!=active": sum(bool(o.get("revoked") or o.get("x_mitre_deprecated")) for o in tech),
    }
    rows["kev_vulnerability_ransomware_known"] = sum(v["knownRansomwareCampaignUse"] == "Known" for v in kev)
    return {"rows": rows, "nulls": nulls}


def check_reconcile(tables: dict[str, pd.DataFrame], exp: dict[str, Any]) -> list[CheckResult]:
    out = []
    for t, n in exp["rows"].items():
        if t in tables:
            out.append(_r("reconcile", f"{t}: rows == independent recount", len(tables[t]) == n, f"clean {len(tables[t])} vs raw {n}"))
    kev, nvd, pk, att, cw, kc = (tables[k] for k in ("kev_vulnerability", "nvd_cve", "pkev_mapping", "attack_technique", "nvd_cve_cwe", "kev_cwe"))
    got = {
        "nvd_cve.cvss_v31_score": int(nvd.cvss_v31_score.isna().sum()),
        "nvd_cve.cvss_v31_type=Secondary": int((nvd.cvss_v31_type == "Secondary").sum()),
        "nvd_cve.cvss_v2_score": int(nvd.cvss_v2_score.isna().sum()),
        "pkev_mapping.comments": int(pk.comments.isna().sum()),
        "kev.due_before_added": int(kev.due_before_added.sum()),
        "kev.no_cwes": int((~kev.cve_id.isin(kc.cve_id)).sum()),
        "nvd_cve_cwe.noninformative": int((~cw.is_informative).sum()),
        "attack_technique.status!=active": int((att.status != "active").sum()),
        "pkev_mapping_reference.not_http_url": int((~tables["pkev_mapping_reference"].is_http_url).sum()),
    }
    for k, v in got.items():
        out.append(_r("reconcile", f"{k} == independent recount", v == exp["nulls"][k], f"clean {v} vs raw {exp['nulls'][k]}"))
    out.append(_r("reconcile", "kev ransomware 'known' == raw", int((kev.ransomware_use == "known").sum()) == exp["rows"]["kev_vulnerability_ransomware_known"]))
    return out


# --------------------------------------------------------------------------- #
# provenance
# --------------------------------------------------------------------------- #
def check_provenance(clean_dir: Path, clean_manifest: dict, raw_dir: Path, raw_manifest: dict, tables: dict[str, pd.DataFrame]) -> list[CheckResult]:
    out = []
    clean_dir = Path(clean_dir)
    for name, rec in clean_manifest["tables"].items():
        p = clean_dir / rec["file"]
        out.append(_r("provenance", f"{name}: file sha256 == clean manifest", p.is_file() and sha256_file(p) == rec["sha256"]))
        out.append(_r("provenance", f"{name}: read -> serialize reproduces the same bytes (lossless round trip)",
                      sha256_bytes(C.serialize(tables[name], name)) == rec["sha256"]))
        out.append(_r("provenance", f"{name}: rows == manifest", len(tables[name]) == rec["rows"]))
    out.append(_r("provenance", "clean manifest records the current raw manifest hash",
                  clean_manifest.get("raw_manifest_sha256") == sha256_file(Path(raw_dir) / "manifest.json")))
    try:
        n = C.verify_raw_inputs(raw_dir, raw_manifest)
        out.append(_r("provenance", "raw files untouched (all match Phase-1 manifest)", True, f"{n} files"))
    except Exception as exc:  # noqa: BLE001
        out.append(_r("provenance", "raw files untouched (all match Phase-1 manifest)", False, str(exc)))
    out.append(_r("provenance", "every rule counter belongs to a documented assumption",
                  all(k.split(".")[0] in C.ASSUMPTIONS for k in clean_manifest["rule_counts"])))
    return out


# --------------------------------------------------------------------------- #
# cross-source consistency (informational, numbers pinned in the registry)
# --------------------------------------------------------------------------- #
def cross_source_report(tables: dict[str, pd.DataFrame], raw: dict[str, Any]) -> dict[str, int]:
    kev, nvd, kc, nc = tables["kev_vulnerability"], tables["nvd_cve"], tables["kev_cwe"], tables["nvd_cve_cwe"]
    pk, att = tables["pkev_mapping"], tables["attack_technique"]
    kset = kc.groupby("cve_id").cwe_id.agg(set)
    nset = nc[nc.is_informative].groupby("cve_id").cwe_id.agg(set)
    both = kset.index.intersection(nset.index)
    echo = {"dateAdded": "cisaExploitAdd", "dueDate": "cisaActionDue", "vulnerabilityName": "cisaVulnerabilityName",
            "requiredAction": "cisaRequiredAction"}
    kv = {v["cveID"]: v for v in raw["kev"]["vulnerabilities"]}
    echo_missing = sum(raw["nvd"][c].get("cisaExploitAdd") is None for c in kv)
    echo_diff = sum(r.get(b) is not None and str(r[b]).strip() != str(kv[c][a]).strip()
                    for c, r in raw["nvd"].items() for a, b in echo.items())
    kn = kev.set_index("cve_id").vulnerability_name
    tn = att.set_index("technique_id").name
    raw_pk = raw["pkev"]["mapping_objects"]
    return {
        "kev_cves_with_pkev_mapping": int(pk.cve_id.nunique()),
        "kev_cves_without_pkev_mapping": int(len(kev) - pk.cve_id.nunique()),
        "kev_and_nvd_both_have_informative_cwe": int(len(both)),
        "kev_nvd_cwe_sets_equal": int(sum(kset[c] == nset[c] for c in both)),
        "kev_nvd_cwe_sets_disjoint": int(sum(not (kset[c] & nset[c]) for c in both)),
        "kev_added_before_nvd_published": int((kev.set_index("cve_id").date_added.dt.tz_localize("UTC") < nvd.set_index("cve_id").published.dt.normalize()).sum()),
        "nvd_missing_kev_echo_fields": int(echo_missing),
        "nvd_kev_echo_value_differences": int(echo_diff),
        "pkev_technique_name_differs_from_attack": int(sum(r["attack_object_name"].strip() != tn[r["attack_object_id"]] for r in raw_pk)),
        "pkev_cve_description_differs_from_kev_name": int(sum(r["capability_description"].strip() != kn[r["capability_id"]] for r in raw_pk)),
    }


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def assert_all(results) -> None:
    failed = [r for r in results if not r.ok]
    if failed:
        raise AssertionError(f"{len(failed)} clean-data check(s) failed:\n" +
                             "\n".join(f"  [{r.family}] {r.name}: {r.detail}" for r in failed))


def write_report(path: Path, results, meta: dict) -> dict:
    from dataclasses import asdict
    from .manifest import utc_now_iso
    doc = {"phase": 2, "generated_at_utc": utc_now_iso(), **meta, "summary": summarize(results),
           "all_passed": all(r.ok for r in results), "checks": [asdict(r) for r in results]}
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc
