"""Phase 2 -- quick data-quality profile of a DataFrame (used in notebook 02).

Answers, per column: how many NULLs, how many empty/blank strings, how many
values with leading/trailing whitespace, how many distinct values. Evidence for
the cleaning rules, not a cleaning step itself.
"""
from __future__ import annotations

import pandas as pd


def profile_frame(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for c in df.columns:
        s = df[c]
        is_text = s.map(lambda x: isinstance(x, str)).any()
        txt = s[s.map(lambda x: isinstance(x, str))]
        rows.append({
            "column": c,
            "kind": "text" if is_text else str(s.dtype),
            "rows": len(s),
            "nulls": int(s.isna().sum()),
            "empty_lists": int(s.map(lambda x: isinstance(x, list) and len(x) == 0).sum()),
            "blank_strings": int((txt.str.strip() == "").sum()) if is_text else 0,
            "edge_whitespace": int((txt != txt.str.strip()).sum()) if is_text else 0,
            "distinct": int(s.map(lambda x: repr(x)).nunique()),
        })
    return pd.DataFrame(rows).set_index("column")