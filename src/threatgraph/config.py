"""Paths and the pinned-source registry.

The registry (config/sources.yaml) is the single place where URLs, commits,
expected hashes and expected counts live. Code never hard-codes them.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import yaml

# ROOT = repository root. Can be overridden (useful in tests / other machines).
ROOT = Path(os.environ.get("THREATGRAPH_ROOT", Path(__file__).resolve().parents[2])).resolve()

CONFIG_DIR = ROOT / "config"
SOURCES_PATH = CONFIG_DIR / "sources.yaml"

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
CLEAN_DIR = DATA_DIR / "clean"
SNAPSHOT_DIR = DATA_DIR / "snapshots"

MANIFEST_PATH = RAW_DIR / "manifest.json"
REPORT_PATH = RAW_DIR / "phase1_validation_report.json"


def load_sources(path: Path = SOURCES_PATH) -> dict[str, Any]:
    """Load the registry as a plain dict."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def sources_digest(path: Path = SOURCES_PATH) -> str:
    """SHA-256 of the registry file itself (stored in the manifest, so that
    a manifest can be tied to the exact configuration that produced it)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
