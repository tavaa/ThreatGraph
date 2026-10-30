# Phase 5 — Snapshots and differences: design notes

Labels: [LITERATURE] supported by a source · [INFERENCE] own reasoning · [PROPOSAL] our choice · [UNCERTAIN] not verified.

## 1. What was built
| Piece | File | Idea |
|---|---|---|
| Snapshot | `src/threatgraph/snapshot.py`, `webapp/catalog/management/commands/snapshot_db.py` | the database frozen as `data/snapshots/<label>/` = `tables/*.csv` + `snapshot.json` + `snapshot.jsonld` |
| Fixity | `verify_snapshot` | recompute every hash, size, row count, header, `content_id`; detect missing/extra files |
| Diff | `diff_snapshots`, `Diff` | rows added / removed / changed (cell by cell) per table, grouped by CVE |
| Diff proof | `apply_diff` | baseline + diff must equal the new snapshot |
| Command line | `python -m threatgraph.snapshot verify / diff` | exit codes 0 / 1 / 2 |
| Description | `jsonld.snapshot_node` | DCAT dataset, versions linked with `prov:wasRevisionOf` |

## 2. Decisions and trade-offs
| Decision [PROPOSAL] | Why | Alternative and its cost |
|---|---|---|
| Snapshot = the 9 CSV tables written by the **same serializer as Phase 2**, read back from the **database** | the baseline hashes equal the Phase-2 manifest: the chain raw → clean → database → snapshot is checkable end to end | database dump (SQLite file): depends on the engine, not byte-reproducible |
| `content_id` = SHA-256 of the table hashes only | same data ⇒ same id on any machine/time/label; one byte changed ⇒ new id | hash of the whole folder: would change with the creation time |
| Append-only; files 0444; folder appears atomically (`.part` then rename) | history cannot be rewritten or half-written by accident | overwrite in place: simple, but no archive |
| Diff by **natural key** (`cve_id`, `technique_id`, …); `mapping_id` and `src_row` ignored | they are positions in a file; one new line at the top of the PKEV file would otherwise change ~1,200 rows | compare by position / by surrogate id: huge fake diffs |
| Evidence rows are matched through the **mapping's natural key**, not through `mapping_id` | same reason | — |
| Diff on **strings** read from the files (`''` = NULL) | no type guessing, no NaN problems; "changed" = the bytes of that cell differ | typed comparison: dtype pitfalls (float 9.8 vs 9.80) |
| Diff is checked by **ground truth + independent recount + patch property + inverse** | a diff that "looks plausible" is not a proof | eyeballing |
| Second version is **synthetic** with a written list of changes | we have only one real upstream version (2025-07-28) | real second version: needs re-running Phases 1–3 with new pins — possible, not done |

## 3. Problems the checks found
1. While building the notebook, the ground-truth table disagreed with the diff on `kev_cwe`. The diff was right; my template CVE had no `kev_cwe` row, so my "+1" was never added. Fixed the construction and added an assertion that each clone really adds one row.
2. (Design, found while thinking about `mapping_id`) A naive diff would report all mappings as changed after one insertion. Test `trap` proves: 1,180 mappings change position, 1 is reported.

## 4. Known limits
* **Synthetic** second version: correct on the written changes, not proof for every real upstream surprise (vendor renames, revoked techniques replaced by others).
* `content_id` is a fixity hash, **not a signature**: someone who can rewrite a snapshot and its manifest can forge both. External signing/timestamping would be needed [UNCERTAIN, not done].
* A re-assigned natural key (e.g. a CVE id corrected) looks like one removal + one addition.
* The diff compares the 9 tables, it does not explain *why* something changed.
* Each snapshot copies the data (~3.5 MB): fine here, not a strategy for big archives.
* A real second snapshot path (new pins → notebooks 01–04 → `snapshot_db --previous …`) is **untested**.

## 5. Exam questions (try before reading the notes)
1. What is a snapshot here, and which OAIS ideas does it use (fixity, provenance, immutability)? What is missing to be a real OAIS archive?
2. Why is `content_id` computed from the table hashes and not from the whole folder? What does that give for reproducibility?
3. Why does the diff ignore `mapping_id`? Give a concrete example of the fake diff you would get otherwise.
4. Why is the diff computed on strings from the files and not on typed values?
5. How do you prove a diff correct when you have no second real version? Name the four proofs.
6. What does the patch property (A + diff = B) prove, and what does it *not* prove?
7. What is the difference between "bytes changed" and "meaning changed"? Which of the two is `content_id`, which is the diff?
8. Which attacks does `verify` stop, and which ones not? (Hint: attacker who can edit both the table and the manifest.)
9. How would you take the second real snapshot, and what could go wrong with the natural keys?
10. How does the snapshot description (DCAT/PROV) link versions, and why are snapshot IRIs built from the content hash?
