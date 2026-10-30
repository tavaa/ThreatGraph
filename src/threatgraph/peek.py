"""Small helpers to *show* what the raw files look like (used in notebook 01).

They return pandas DataFrames / short strings; they never modify data.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def pretty(obj: Any, max_chars: int = 1200) -> str:
    s = json.dumps(obj, indent=2, ensure_ascii=False)
    return s if len(s) <= max_chars else s[:max_chars] + "\n  ... [truncated]"


def kev_overview(doc: dict) -> dict:
    df = pd.DataFrame(doc["vulnerabilities"])
    return {
        "header": {k: doc[k] for k in ("title", "catalogVersion", "dateReleased", "count")},
        "first_entry": doc["vulnerabilities"][0],
        "ransomware": df["knownRansomwareCampaignUse"].value_counts().to_dict(),
        "top_vendors": df["vendorProject"].value_counts().head(5).to_dict(),
        "dateAdded_range": (df["dateAdded"].min(), df["dateAdded"].max()),
        "frame": df,
    }


def pkev_overview(doc: dict) -> dict:
    df = pd.DataFrame(doc["mapping_objects"])
    return {
        "metadata": doc["metadata"],
        "first_row": doc["mapping_objects"][0],
        "mapping_type": df["mapping_type"].value_counts().to_dict(),
        "top_techniques": df.groupby(["attack_object_id", "attack_object_name"]).size().sort_values(ascending=False).head(5),
        "frame": df,
    }


def attack_overview(doc: dict) -> dict:
    objs = doc["objects"]
    types = pd.Series([o["type"] for o in objs]).value_counts()
    tech = next(o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"))
    short = {k: tech[k] for k in ("type", "id", "name", "kill_chain_phases", "modified") if k in tech}
    short["external_id"] = next(r["external_id"] for r in tech["external_references"] if r["source_name"] == "mitre-attack")
    return {"bundle": {k: doc[k] for k in ("type", "id", "spec_version")}, "type_counts": types, "sample_technique": short}


def nvd_overview(rec: dict) -> dict:
    desc = next((d["value"] for d in rec["descriptions"] if d.get("lang") == "en"), "")
    return {
        "keys": sorted(rec),
        "summary": {k: rec.get(k) for k in ("id", "sourceIdentifier", "published", "lastModified", "vulnStatus")},
        "description_en": desc[:200] + ("..." if len(desc) > 200 else ""),
        "n_references": len(rec.get("references", [])),
        "metrics_keys": sorted(rec.get("metrics", {})),
    }
