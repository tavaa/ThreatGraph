"""Snapshots and differences (Phase 5).

A SNAPSHOT freezes the 9 tables of the database at one moment as a folder:

    data/snapshots/<label>/
        tables/<table>.csv        deterministic CSV bytes (same serializer as Phase 2)
        snapshot.json             manifest: sizes, SHA-256 of every table, content_id, provenance, previous snapshot
        snapshot.jsonld           the same description as DCAT/PROV JSON-LD (versions linked with prov:wasRevisionOf)

Design [PROPOSAL, OAIS-style Archival Information Package, FAIR R1.2 provenance]
* ``content_id`` = SHA-256 of the list of (table, table-hash) pairs. It depends ONLY on the data bytes: not on the
  label, not on the creation time, not on the machine. Same data => same id (reproducible); one changed byte => new id.
* Append-only: a label that already exists is never overwritten (identical content => no-op, different => error).
  Files are made read-only (0444).
* ``diff`` is SEMANTIC, ``content_id`` is BYTE-level. The diff compares rows by NATURAL KEY (cve_id, technique_id,
  ...) and ignores POSITIONAL columns (``mapping_id`` = line number in the PKEV file, ``src_row``): otherwise one new
  PKEV line at the top of the file would make all 1,183 mappings look "changed".
* A diff is checked by ``apply_diff``: old snapshot + diff must give exactly the new snapshot.

Pure Python + pandas, no Django. Command line:  python -m threatgraph.snapshot verify DIR | diff DIR_A DIR_B
"""
from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from . import cleaning as C
from . import jsonld
from .integrity import sha256_bytes, sha256_file
from .manifest import utc_now_iso

SNAPSHOT_SCHEMA = 1
TABLES = list(C.SCHEMA)                                   # the 9 clean tables, in schema order


class SnapshotError(RuntimeError):
    pass


class SnapshotExists(SnapshotError):
    """The label exists with DIFFERENT content (snapshots are append-only)."""


class DiffError(SnapshotError):
    pass


# ----------------------------------------------------------------------------- identity
def count_rows(b: bytes) -> int:
    """Data rows of a CSV (quoted fields may contain line breaks, so counting '\\n' would be wrong)."""
    return len(pd.read_csv(io.BytesIO(b), dtype=str, keep_default_na=False))


def content_id(table_hashes: dict[str, str]) -> str:
    """SHA-256 over 'table<TAB>sha256' lines, sorted by table name, plus the snapshot schema version."""
    lines = [f"schema\t{SNAPSHOT_SCHEMA}"] + [f"{t}\t{table_hashes[t]}" for t in sorted(table_hashes)]
    return sha256_bytes("\n".join(lines).encode("utf-8"))


def provenance_from(clean_manifest: dict, sources: dict) -> dict:
    """What the data were made from: raw files, cleaning code, pinned upstream versions."""
    return {"common_version": sources["common_version"]["label"],
            "raw_manifest_sha256": clean_manifest.get("raw_manifest_sha256"),
            "cleaning_code_sha256": clean_manifest.get("cleaning_code_sha256"),
            "sources_digest_sha256": clean_manifest.get("sources_digest_sha256"),
            "pinned_refs": {k: v["pinned_ref"] for k, v in sources["sources"].items()}}


# ----------------------------------------------------------------------------- create / read / verify
def frame_to_csv(df: pd.DataFrame, table: str) -> bytes:
    """CSV bytes of a frame of STRINGS (as returned by read_tables), sorted by primary key. For synthetic snapshots."""
    out = df[list(C.SCHEMA[table].columns)].sort_values(C.SCHEMA[table].pk, kind="stable")
    return out.to_csv(index=False, lineterminator="\n").encode("utf-8")


def create_snapshot(tables: dict[str, pd.DataFrame] | None, root: str | Path, label: str, provenance: dict | None = None,
                    previous: str | Path | None = None, csv_bytes: dict[str, bytes] | None = None) -> Path:
    """Write ``root/label``. ``tables`` = typed frames (Phase-2 dtypes), or ``csv_bytes`` = ready CSV bytes per table.
    ``previous`` = folder of the snapshot this one is a revision of. Returns the folder."""
    if csv_bytes is None:
        csv_bytes = {t: C.serialize(tables[t], t) for t in TABLES}
    if set(csv_bytes) != set(TABLES):
        raise SnapshotError(f"need exactly the tables {TABLES}, got {sorted(csv_bytes)}")
    hashes = {t: sha256_bytes(b) for t, b in csv_bytes.items()}
    cid = content_id(hashes)
    prev_id = read_manifest(previous)["content_id"] if previous else None
    dest = Path(root) / label
    if dest.exists():
        old = read_manifest(dest)["content_id"]
        if old == cid:
            return dest                                               # idempotent: nothing to do
        raise SnapshotExists(f"{dest} exists with content_id {old[:12]}…, new data would be {cid[:12]}…")
    tmp = dest.with_name(dest.name + ".part")
    shutil.rmtree(tmp, ignore_errors=True)
    (tmp / "tables").mkdir(parents=True)
    for t, b in csv_bytes.items():
        (tmp / "tables" / f"{t}.csv").write_bytes(b)
    manifest = {"snapshot_schema": SNAPSHOT_SCHEMA, "label": label, "content_id": cid, "created_at_utc": utc_now_iso(),
                "previous_content_id": prev_id, "provenance": provenance or {},
                "tables": {t: {"file": f"tables/{t}.csv", "rows": count_rows(b), "bytes": len(b), "sha256": hashes[t]}
                           for t, b in csv_bytes.items()}}
    (tmp / "snapshot.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (tmp / "snapshot.jsonld").write_text(json.dumps(jsonld.document(jsonld.snapshot_node(manifest)), indent=2) + "\n",
                                         encoding="utf-8")
    tmp.rename(dest)                                                  # appears all at once, never half-written
    for p in dest.rglob("*"):
        if p.is_file():
            p.chmod(0o444)
    return dest


def make_writable(folder: str | Path) -> None:
    """Undo the read-only flag (needed to delete a snapshot copy, e.g. in tests)."""
    for p in Path(folder).rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)


def read_manifest(folder: str | Path) -> dict:
    return json.loads((Path(folder) / "snapshot.json").read_text(encoding="utf-8"))


def read_tables(folder: str | Path) -> dict[str, pd.DataFrame]:
    """All tables as frames of STRINGS (no type guessing: '' = NULL). Exactly what is on disk."""
    return {t: pd.read_csv(Path(folder) / "tables" / f"{t}.csv", dtype=str, keep_default_na=False) for t in TABLES}


def verify_snapshot(folder: str | Path) -> list[str]:
    """Fixity check. Returns the list of problems (empty list = intact)."""
    folder = Path(folder)
    problems: list[str] = []
    try:
        m = read_manifest(folder)
    except (OSError, ValueError) as e:
        return [f"manifest unreadable: {e}"]
    if set(m.get("tables", {})) != set(TABLES):
        problems.append(f"manifest lists tables {sorted(m.get('tables', {}))}")
    on_disk = {p.name for p in (folder / "tables").glob("*")} if (folder / "tables").is_dir() else set()
    for extra in sorted(on_disk - {f"{t}.csv" for t in TABLES}):
        problems.append(f"unexpected file tables/{extra}")
    for t, info in m.get("tables", {}).items():
        p = folder / info["file"]
        if not p.is_file():
            problems.append(f"{t}: file missing")
            continue
        if p.stat().st_size != info["bytes"]:
            problems.append(f"{t}: size {p.stat().st_size} != manifest {info['bytes']}")
        if sha256_file(p) != info["sha256"]:
            problems.append(f"{t}: SHA-256 differs from manifest")
            continue
        header = p.read_text(encoding="utf-8").split("\n", 1)[0]
        if header != ",".join(C.SCHEMA[t].columns):
            problems.append(f"{t}: header {header!r} != schema")
        if count_rows(p.read_bytes()) != info["rows"]:
            problems.append(f"{t}: row count differs from manifest")
    try:
        if content_id({t: i["sha256"] for t, i in m["tables"].items()}) != m["content_id"]:
            problems.append("content_id does not match the table hashes in the manifest")
    except KeyError:
        problems.append("manifest incomplete")
    return problems


# ----------------------------------------------------------------------------- diff
@dataclass(frozen=True)
class Spec:
    key: tuple[str, ...]
    ignore: tuple[str, ...] = ()


# natural keys; positional columns are ignored (see module docstring)
DIFF_SPEC: dict[str, Spec] = {
    "kev_vulnerability": Spec(("cve_id",), ("src_row",)),
    "kev_cwe": Spec(("cve_id", "cwe_id")),
    "nvd_cve": Spec(("cve_id",)),
    "nvd_cve_cwe": Spec(("cve_id", "cwe_id", "source")),
    "attack_tactic": Spec(("tactic_id",)),
    "attack_technique": Spec(("technique_id",)),
    "attack_technique_tactic": Spec(("technique_id", "tactic_id")),
    "pkev_mapping": Spec(("cve_id", "technique_id", "mapping_type"), ("mapping_id",)),
    "pkev_mapping_reference": Spec(("cve_id", "technique_id", "mapping_type", "reference")),
}


def normalize(tables: dict[str, pd.DataFrame]) -> dict[str, pd.DataFrame]:
    """Frames indexed by natural key, positional columns dropped. pkev_mapping_reference points to its mapping by
    mapping_id (positional): replace that by the mapping's natural key."""
    t = {k: v.copy() for k, v in tables.items()}
    m = t["pkev_mapping"][["mapping_id", "cve_id", "technique_id", "mapping_type"]]
    t["pkev_mapping_reference"] = t["pkev_mapping_reference"].merge(m, on="mapping_id", how="left", validate="many_to_one")
    if t["pkev_mapping_reference"]["cve_id"].isna().any():
        raise DiffError("pkev_mapping_reference points to a mapping_id that does not exist")
    out = {}
    for name, df in t.items():
        spec = DIFF_SPEC[name]
        cols = [c for c in df.columns if c not in spec.ignore and c != "mapping_id"] if name == "pkev_mapping_reference" \
            else [c for c in df.columns if c not in spec.ignore]
        df = df[cols]
        if df.duplicated(list(spec.key)).any():
            raise DiffError(f"{name}: natural key {spec.key} is not unique")
        out[name] = df.set_index(list(spec.key)).sort_index()
    return out


@dataclass
class TableDiff:
    key: tuple[str, ...]
    added: pd.DataFrame            # rows only in B   (key columns + values)
    removed: pd.DataFrame          # rows only in A
    changed: pd.DataFrame          # one line per changed CELL: key columns, column, old, new

    @property
    def n_changed_rows(self) -> int:
        return len(self.changed.drop_duplicates(list(self.key))) if len(self.changed) else 0

    @property
    def empty(self) -> bool:
        return not (len(self.added) or len(self.removed) or len(self.changed))


@dataclass
class Diff:
    a: dict
    b: dict
    tables: dict[str, TableDiff] = field(default_factory=dict)

    @property
    def identical(self) -> bool:
        return all(td.empty for td in self.tables.values())

    def summary(self) -> pd.DataFrame:
        return pd.DataFrame([{"table": t, "added": len(d.added), "removed": len(d.removed),
                              "changed rows": d.n_changed_rows, "changed cells": len(d.changed)}
                             for t, d in self.tables.items()]).set_index("table")

    def by_cve(self) -> dict[str, list[str]]:
        """Human changelog grouped by CVE (every table whose key contains cve_id)."""
        log: dict[str, list[str]] = {}
        for t, d in self.tables.items():
            if "cve_id" not in d.key:
                continue
            rest = [k for k in d.key if k != "cve_id"]
            tag = lambda row: "/".join(_short(str(row[k]), 30) for k in rest)
            for _, r in d.added.iterrows():
                log.setdefault(r["cve_id"], []).append(f"+ {t} {tag(r)}".rstrip())
            for _, r in d.removed.iterrows():
                log.setdefault(r["cve_id"], []).append(f"- {t} {tag(r)}".rstrip())
            for _, r in d.changed.iterrows():
                where = f"{t} {tag(r)}".strip()
                log.setdefault(r["cve_id"], []).append(f"~ {where} [{r['column']}] {_short(r['old'])} -> {_short(r['new'])}")
        return {k: sorted(v) for k, v in sorted(log.items())}

    def to_dict(self) -> dict:
        return {"from": self.a, "to": self.b, "identical": self.identical,
                "summary": self.summary().reset_index().to_dict("records"),
                "by_cve": self.by_cve(),
                "other_tables": {t: {"added": d.added.to_dict("records"), "removed": d.removed.to_dict("records"),
                                      "changed": d.changed.to_dict("records")}
                                 for t, d in self.tables.items() if "cve_id" not in d.key and not d.empty}}


def _short(x: str, n: int = 40) -> str:
    x = "(empty)" if x == "" else x
    return x if len(x) <= n else x[: n - 1] + "…"


def diff_tables(a: dict[str, pd.DataFrame], b: dict[str, pd.DataFrame], a_info: dict | None = None,
                b_info: dict | None = None) -> Diff:
    """Compare two sets of STRING frames (as read_tables gives them)."""
    A, B = normalize(a), normalize(b)
    out = Diff(a_info or {}, b_info or {})
    for t in TABLES:
        key = list(DIFF_SPEC[t].key)
        if list(A[t].columns) != list(B[t].columns):
            raise DiffError(f"{t}: columns differ {list(A[t].columns)} vs {list(B[t].columns)}")
        ia, ib = A[t].index, B[t].index
        added = B[t].loc[ib.difference(ia)].reset_index()
        removed = A[t].loc[ia.difference(ib)].reset_index()
        common = ia.intersection(ib)
        x, y = A[t].loc[common], B[t].loc[common]
        rows = []
        for c in x.columns:
            m = (x[c] != y[c]).to_numpy()
            if m.any():
                part = pd.DataFrame({"column": c, "old": x[c][m].to_numpy(), "new": y[c][m].to_numpy()}, index=x.index[m])
                rows.append(part.reset_index())
        changed = pd.concat(rows, ignore_index=True) if rows else pd.DataFrame(columns=[*key, "column", "old", "new"])
        out.tables[t] = TableDiff(tuple(key), added, removed, changed.sort_values([*key, "column"]).reset_index(drop=True))
    return out


def diff_snapshots(folder_a: str | Path, folder_b: str | Path) -> Diff:
    """Diff two snapshot folders. Refuses to compare a damaged snapshot."""
    for f in (folder_a, folder_b):
        bad = verify_snapshot(f)
        if bad:
            raise SnapshotError(f"{f} failed verification: {bad[:3]}")
    ma, mb = read_manifest(folder_a), read_manifest(folder_b)
    info = lambda m: {"label": m["label"], "content_id": m["content_id"]}
    return diff_tables(read_tables(folder_a), read_tables(folder_b), info(ma), info(mb))


def apply_diff(a: dict[str, pd.DataFrame], diff: Diff) -> dict[str, pd.DataFrame]:
    """A + diff -> B (normalized, indexed by natural key). If this is not equal to normalize(B), the diff is wrong."""
    A = normalize(a)
    out = {}
    for t, d in diff.tables.items():
        key = list(d.key)
        df = A[t].drop(index=pd.MultiIndex.from_frame(d.removed[key]) if len(key) > 1 else pd.Index(d.removed[key[0]]))
        for _, r in d.changed.iterrows():
            df.loc[tuple(r[k] for k in key) if len(key) > 1 else r[key[0]], r["column"]] = r["new"]
        add = d.added.set_index(key)
        df = pd.concat([df, add[df.columns]]) if len(add) else df
        out[t] = df.sort_index()
    return out


# ----------------------------------------------------------------------------- command line
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m threatgraph.snapshot", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check the fixity of a snapshot folder (exit 0 = intact, 1 = damaged)")
    v.add_argument("folder")
    d = sub.add_parser("diff", help="differences between two snapshot folders (exit 0 = identical, 1 = different)")
    d.add_argument("folder_a")
    d.add_argument("folder_b")
    d.add_argument("--json", help="also write the full diff to this file")
    a = p.parse_args(argv)
    try:
        if a.cmd == "verify":
            bad = verify_snapshot(a.folder)
            print("OK: snapshot intact" if not bad else "DAMAGED:\n  " + "\n  ".join(bad))
            return 1 if bad else 0
        df = diff_snapshots(a.folder_a, a.folder_b)
        print(f"{df.a.get('label')} ({df.a.get('content_id', '')[:12]}) -> {df.b.get('label')} ({df.b.get('content_id', '')[:12]})")
        print("IDENTICAL" if df.identical else df.summary().to_string())
        if a.json:
            Path(a.json).write_text(json.dumps(df.to_dict(), indent=1, default=str) + "\n", encoding="utf-8")
        return 0 if df.identical else 1
    except SnapshotError as e:
        print("ERROR:", e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
