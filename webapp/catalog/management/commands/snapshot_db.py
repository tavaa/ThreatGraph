"""python manage.py snapshot_db --label 2025-07-28 [--root ../data/snapshots] [--previous ../data/snapshots/<old>]

Freezes the CURRENT DATABASE into data/snapshots/<label>/ (9 CSV tables + snapshot.json + snapshot.jsonld).
The tables are read back from the database (not copied from data/clean/), so the snapshot proves what the database
really contains. Append-only: an existing label with the same content is a no-op, with different content an error.
"""
import json
import sys
from pathlib import Path

import pandas as pd
from django.core.management.base import BaseCommand, CommandError

ROOT = Path(__file__).resolve().parents[4]          # repo root
sys.path.insert(0, str(ROOT / "src"))

from threatgraph import cleaning as C, config, snapshot as SN       # noqa: E402

import catalog.models as M                                           # noqa: E402

TABLE2MODEL = {"kev_vulnerability": M.Vulnerability, "kev_cwe": M.KevCwe, "nvd_cve": M.NvdRecord,
               "nvd_cve_cwe": M.NvdCveCwe, "attack_tactic": M.AttackTactic, "attack_technique": M.AttackTechnique,
               "attack_technique_tactic": M.AttackTechniqueTactic, "pkev_mapping": M.PkevMapping,
               "pkev_mapping_reference": M.PkevMappingReference}


def db_frame(table, model):
    """One table read from the database, with the Phase-2 dtypes (so that C.serialize gives the Phase-2 bytes)."""
    spec = C.SCHEMA[table]
    if table == "nvd_cve_cwe":
        df = pd.DataFrame(list(model.objects.values("cve_id", "cwe_id", "source", "type", "cwe__is_informative"))) \
            .rename(columns={"cwe__is_informative": "is_informative"})
    else:
        df = pd.DataFrame(list(model.objects.values()))
    df = df[list(spec.columns)]
    for c, col in spec.columns.items():
        if col.dtype == "date":
            df[c] = pd.to_datetime(df[c])
        elif col.dtype == "datetime":
            df[c] = pd.to_datetime(df[c], utc=True)
        elif col.dtype == "int":
            df[c] = df[c].astype("Int64")
        elif col.dtype == "float":
            df[c] = df[c].astype("float64")
        elif col.dtype == "bool":
            df[c] = df[c].astype(bool)
        else:
            df[c] = df[c].astype("string")
    return df


def db_tables():
    return {t: db_frame(t, m) for t, m in TABLE2MODEL.items()}


class Command(BaseCommand):
    help = "Freeze the database into a hashed, read-only snapshot folder."

    def add_arguments(self, parser):
        parser.add_argument("--label", help="folder name; default = common_version label of config/sources.yaml")
        parser.add_argument("--root", default=str(config.SNAPSHOT_DIR))
        parser.add_argument("--previous", help="snapshot folder this one is a revision of")

    def handle(self, *args, **opts):
        sources = config.load_sources()
        label = opts["label"] or sources["common_version"]["label"]
        manifest_path = config.CLEAN_DIR / "manifest.json"
        if not manifest_path.exists():
            raise CommandError("data/clean/manifest.json not found: run Phase 2 first")
        prov = SN.provenance_from(json.loads(manifest_path.read_text()), sources)
        try:
            dest = SN.create_snapshot(db_tables(), opts["root"], label, prov, previous=opts["previous"])
        except SN.SnapshotError as e:
            raise CommandError(str(e))
        m = SN.read_manifest(dest)
        self.stdout.write(f"snapshot {dest}\ncontent_id {m['content_id']}\n" +
                          "\n".join(f"  {t:26} {i['rows']:>6} rows  {i['sha256'][:12]}…" for t, i in m["tables"].items()))
