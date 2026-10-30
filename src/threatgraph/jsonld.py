"""JSON-LD view of the ThreatGraph data (Phase 4).

Pure Python, NO Django import: the functions take the plain dictionaries produced by the REST serializers
(catalog/serializers.py) and return JSON-LD nodes. So the JSON and the JSON-LD representations come from ONE
source and cannot drift apart. A dedicated test (notebook 05) checks that they say the same thing.

Design decisions
----------------
* ``@id`` of a thing = the canonical public IRI of that thing (NVD page of the CVE, ATT&CK page of the
  technique, CWE page of the weakness). Graphs published by other people about the same CVE or technique
  therefore merge with ours automatically (FAIR I3: qualified references; F1: global identifier).   [PROPOSAL]
* The URL of our own API page for the same thing goes in ``apiUrl``.
* NULL / unknown values are OMITTED (in JSON-LD "absent property" = "not stated"; never an empty string).
* A PKEV mapping is a node of its own (``Mapping``, reified association class) because it has attributes
  (type, comments, evidence). Its IRI ``urn:threatgraph:pkev-mapping:<n>`` uses the POSITION in the pinned PKEV
  file, so it is stable only for the pinned commit.                                                   [UNCERTAIN]
* Vocabulary: standard terms where a good one exists (Dublin Core Terms, DCAT, PROV-O, XSD); own terms (``tg:``)
  for the domain. VOCAB below is a PLACEHOLDER namespace: a real deployment needs a persistent IRI (e.g. w3id.org).
* Safety net: JSON-LD silently DROPS keys that the @context does not define. ``undefined_terms()`` finds them.
"""
from __future__ import annotations

from typing import Any, Iterable

VOCAB = "https://example.org/threatgraph/vocab#"          # PLACEHOLDER namespace, see module docstring

CONTEXT: dict[str, Any] = {
    # prefixes
    "tg": VOCAB,
    "dcterms": "http://purl.org/dc/terms/",
    "dcat": "http://www.w3.org/ns/dcat#",
    "prov": "http://www.w3.org/ns/prov#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    # classes
    "Vulnerability": "tg:Vulnerability",
    "NvdRecord": "tg:NvdRecord",
    "CvssV31": "tg:CvssV31",
    "Weakness": "tg:Weakness",
    "WeaknessAssignment": "tg:WeaknessAssignment",
    "AttackTechnique": "tg:AttackTechnique",
    "AttackTactic": "tg:AttackTactic",
    "Mapping": "tg:Mapping",
    "Dataset": "dcat:Dataset",
    "Distribution": "dcat:Distribution",
    # generic
    "apiUrl": {"@id": "tg:apiUrl", "@type": "@id"},
    "wasDerivedFrom": {"@id": "prov:wasDerivedFrom", "@type": "@id", "@container": "@set"},
    "name": "rdfs:label",
    "description": "dcterms:description",
    "title": "dcterms:title",
    # KEV (Vulnerability)
    "cveId": "dcterms:identifier",
    "vendorProject": "tg:vendorProject",
    "product": "tg:product",
    "shortDescription": "tg:shortDescription",
    "requiredAction": "tg:requiredAction",
    "dateAdded": {"@id": "tg:dateAdded", "@type": "xsd:date"},
    "dueDate": {"@id": "tg:dueDate", "@type": "xsd:date"},
    "ransomwareUse": "tg:ransomwareUse",
    "notes": "tg:notes",
    "dueBeforeAdded": "tg:dueBeforeAdded",
    "weakness": {"@id": "tg:weakness", "@container": "@set"},
    "nvd": "tg:nvdRecord",
    "mappings": {"@id": "tg:hasMapping", "@container": "@set"},
    # Weakness
    "cweId": "tg:cweId",
    "isInformative": "tg:isInformative",
    # NVD
    "vulnStatus": "tg:vulnStatus",
    "published": {"@id": "dcterms:issued", "@type": "xsd:dateTime"},
    "nReferences": "tg:nReferences",
    "cvssV31": "tg:cvssV31",
    "cvssV2Score": {"@id": "tg:cvssV2Score", "@type": "xsd:decimal"},
    "score": {"@id": "tg:baseScore", "@type": "xsd:decimal"},
    "severity": "tg:severity",
    "vector": "tg:vector",
    "metricSource": "tg:metricSource",
    "metricType": "tg:metricType",
    "weaknessAssignment": {"@id": "tg:weaknessAssignment", "@container": "@set"},
    "assignedBy": "tg:assignedBy",
    "assignmentType": "tg:assignmentType",
    # ATT&CK
    "techniqueId": "tg:techniqueId",
    "tacticId": "tg:tacticId",
    "shortname": "tg:shortname",
    "status": "tg:status",
    "isSubtechnique": "tg:isSubtechnique",
    "created": {"@id": "dcterms:created", "@type": "xsd:dateTime"},
    "modified": {"@id": "dcterms:modified", "@type": "xsd:dateTime"},   # NVD lastModified, ATT&CK modified, dataset
    "parentTechnique": {"@id": "tg:parentTechnique", "@type": "@id"},
    "subtechnique": {"@id": "tg:subtechnique", "@type": "@id", "@container": "@set"},
    "tactic": {"@id": "tg:tactic", "@container": "@set"},
    # Mapping (PKEV)
    "technique": "tg:technique",
    "vulnerability": "tg:vulnerability",
    "mappingType": "tg:mappingType",
    "capabilityGroup": "tg:capabilityGroup",
    "comments": "tg:comments",
    "evidence": {"@id": "tg:evidence", "@container": "@set"},
    "evidenceUrl": {"@id": "tg:evidenceUrl", "@type": "@id", "@container": "@set"},
    # Dataset (DCAT / PROV)
    "version": "dcterms:hasVersion",
    "publisher": "dcterms:publisher",
    "rights": "dcterms:rights",
    "sha256": "tg:sha256",
    "contentId": "tg:contentId",
    "wasRevisionOf": {"@id": "prov:wasRevisionOf", "@type": "@id"},
    "rawManifestSha256": "tg:rawManifestSha256",
    "cleaningCodeSha256": "tg:cleaningCodeSha256",
    "rowCount": "tg:rowCount",
    "distribution": {"@id": "dcat:distribution", "@container": "@set"},
    "accessURL": {"@id": "dcat:accessURL", "@type": "@id"},
    "mediaType": {"@id": "dcat:mediaType", "@container": "@set"},
    "tables": "tg:tables",
    # paging of list responses
    "totalItems": "tg:totalItems",
    "nextPage": {"@id": "tg:nextPage", "@type": "@id"},
    "previousPage": {"@id": "tg:previousPage", "@type": "@id"},
}

NONINFORMATIVE_PREFIX = "NVD-CWE-"


# ----------------------------------------------------------------------------- identifiers
def vulnerability_iri(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def technique_iri(technique_id: str) -> str:
    """T1059.001 -> https://attack.mitre.org/techniques/T1059/001/  (ATT&CK website pattern)."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def tactic_iri(tactic_id: str) -> str:
    return f"https://attack.mitre.org/tactics/{tactic_id}/"


def cwe_iri(cwe_id: str) -> str:
    """CWE-611 -> cwe.mitre.org page. NVD-CWE-noinfo / NVD-CWE-Other are NVD labels, not CWE entries: local URN."""
    if cwe_id.startswith("CWE-") and cwe_id[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html"
    return f"urn:threatgraph:weakness:{cwe_id}"


def mapping_iri(mapping_id: int) -> str:
    return f"urn:threatgraph:pkev-mapping:{mapping_id}"


def github_commit_iri(repo: str, ref: str) -> str:
    return f"https://github.com/{repo}/tree/{ref}"


def prov_iris(sources: dict) -> dict[str, str]:
    """{'kev': iri, 'nvd': iri, 'attack': iri, 'pkev': iri} from config/sources.yaml."""
    return {k: github_commit_iri(v["repo"], v["pinned_ref"]) for k, v in sources["sources"].items()}


# ----------------------------------------------------------------------------- helpers
def _clean(d: dict) -> dict:
    """Drop None and empty lists: 'not stated' is expressed by absence."""
    return {k: v for k, v in d.items() if v is not None and v != []}


def weakness_node(w: dict) -> dict:
    return _clean({"@id": cwe_iri(w["cwe_id"]), "@type": "Weakness", "cweId": w["cwe_id"],
                   "isInformative": w.get("is_informative")})


def tactic_node(t: dict) -> dict:
    return _clean({"@id": tactic_iri(t["tactic_id"]), "@type": "AttackTactic", "tacticId": t["tactic_id"],
                   "shortname": t.get("shortname"), "name": t.get("name")})


def technique_ref(technique_id: str, name: str | None = None) -> dict:
    return _clean({"@id": technique_iri(technique_id), "@type": "AttackTechnique", "techniqueId": technique_id,
                   "name": name})


# ----------------------------------------------------------------------------- nodes
def mapping_node(m: dict, prov: dict | None = None) -> dict:
    """One PKEV mapping. Used in the vulnerability view (m has technique_*) and in the technique view (m has cve_id)."""
    refs = m.get("references") or []
    node = {"@id": mapping_iri(m["mapping_id"]), "@type": "Mapping",
            "mappingType": m.get("mapping_type"), "capabilityGroup": m.get("capability_group"),
            "comments": m.get("comments"),
            "evidence": [r["reference"] for r in refs if not r["is_http_url"]],
            "evidenceUrl": [r["reference"] for r in refs if r["is_http_url"]],
            "wasDerivedFrom": [prov["pkev"]] if prov and "pkev" in prov else None}
    if m.get("technique_id"):
        t = technique_ref(m["technique_id"], m.get("technique_name"))
        t["tactic"] = [tactic_node(x) for x in m.get("tactics", [])] or None
        node["technique"] = _clean(t)
    if m.get("cve_id"):
        node["vulnerability"] = {"@id": vulnerability_iri(m["cve_id"]), "@type": "Vulnerability", "cveId": m["cve_id"]}
    return _clean(node)


def nvd_node(n: dict, prov: dict | None = None) -> dict:
    cv = n.get("cvss_v31")
    cvss = None if not cv else _clean({"@type": "CvssV31", "score": cv.get("score"), "severity": cv.get("severity"),
                                        "vector": cv.get("vector"), "metricSource": cv.get("source"),
                                        "metricType": cv.get("type")})
    assignments = [_clean({"@type": "WeaknessAssignment", "weakness": [weakness_node(c)], "assignedBy": c.get("source"),
                           "assignmentType": c.get("type")}) for c in n.get("cwes", [])]
    return _clean({"@type": "NvdRecord", "vulnStatus": n.get("status"), "published": n.get("published"),
                   "modified": n.get("last_modified"), "description": n.get("description_en"),
                   "cvssV31": cvss, "cvssV2Score": n.get("cvss_v2_score"), "nReferences": n.get("n_references"),
                   "weaknessAssignment": assignments,
                   "wasDerivedFrom": [prov["nvd"]] if prov and "nvd" in prov else None})


def vulnerability_node(d: dict, prov: dict | None = None) -> dict:
    """Works for the summary (list) and the detail dictionary: missing keys are simply omitted."""
    node = {"@id": vulnerability_iri(d["cve_id"]), "@type": "Vulnerability", "cveId": d["cve_id"],
            "apiUrl": d.get("url"), "vendorProject": d.get("vendor_project"), "product": d.get("product"),
            "title": d.get("vulnerability_name"), "dateAdded": d.get("date_added"),
            "dueDate": d.get("due_date"), "shortDescription": d.get("short_description"),
            "requiredAction": d.get("required_action"), "ransomwareUse": d.get("ransomware_use"),
            "notes": d.get("notes") or None, "dueBeforeAdded": d.get("due_before_added")}
    if "kev_cwes" in d:
        node["weakness"] = [weakness_node(w) for w in d["kev_cwes"]]
    if d.get("nvd"):
        node["nvd"] = nvd_node(d["nvd"], prov)
    if "attack" in d:
        node["mappings"] = [mapping_node(m, prov) for m in d["attack"]]
    if prov and "kev" in prov and "kev_cwes" in d:          # detail only: summaries stay small
        node["wasDerivedFrom"] = [prov["kev"]]
    return _clean(node)


def technique_node(d: dict, prov: dict | None = None) -> dict:
    node = {"@id": technique_iri(d["technique_id"]), "@type": "AttackTechnique", "techniqueId": d["technique_id"],
            "apiUrl": d.get("url"), "name": d.get("name"), "status": d.get("status"),
            "isSubtechnique": d.get("is_subtechnique"), "created": d.get("created"), "modified": d.get("modified"),
            "description": d.get("description")}
    if d.get("parent_technique"):
        node["parentTechnique"] = technique_iri(d["parent_technique"]["technique_id"]
                                                if isinstance(d["parent_technique"], dict) else d["parent_technique"])
    if d.get("subtechniques"):
        node["subtechnique"] = [technique_iri(s["technique_id"]) for s in d["subtechniques"]]
    if d.get("tactics"):
        node["tactic"] = [tactic_node(t) if isinstance(t, dict) else {"@id": tactic_iri(t)} for t in d["tactics"]]
    if "mappings" in d:
        node["mappings"] = [mapping_node({**m, "technique_id": d["technique_id"], "technique_name": d.get("name")}, prov)
                            for m in d["mappings"]]
    if prov and "attack" in prov and "mappings" in d:
        node["wasDerivedFrom"] = [prov["attack"]]
    return _clean(node)


def dataset_node(api_base: str, sources: dict, clean_manifest: dict, counts: dict[str, int]) -> dict:
    """DCAT description of the integrated dataset, with PROV links to the four pinned upstream sources.
    Everything comes from config/sources.yaml and data/clean/manifest.json: nothing is typed by hand."""
    prov = prov_iris(sources)
    derived = []
    for key, s in sources["sources"].items():
        data_file = next((f for f in s["files"] if f["role"] == "data"), None)
        derived.append(_clean({
            "@id": prov[key], "@type": "Dataset", "title": s["title"], "publisher": s["publisher"],
            "version": s["pinned_ref"], "rights": s.get("license"),
            "sha256": data_file["sha256"] if data_file else None}))
    dists = [{"@type": "Distribution", "title": t, "accessURL": api_base + path,
              "mediaType": ["application/json", "application/ld+json"]}
             for t, path in (("Vulnerabilities", "api/vulnerabilities/"), ("ATT&CK techniques", "api/techniques/"),
                             ("ATT&CK tactics", "api/tactics/"), ("Weaknesses (CWE)", "api/cwes/"))]
    return _clean({
        "@id": api_base + "api/dataset/", "@type": "Dataset",
        "title": "ThreatGraph-LD: CISA KEV x NVD x MITRE ATT&CK x CTID PKEV",
        "description": "Open cyber-threat datasets integrated through the CVE identifier (KEV, NVD) and the ATT&CK "
                       "technique identifier (PKEV, ATT&CK). Snapshot " + sources["common_version"]["label"] + ".",
        "version": sources["common_version"]["label"],
        "modified": clean_manifest.get("generated_at_utc"),
        "rawManifestSha256": clean_manifest.get("raw_manifest_sha256"),     # one hash covering all raw files (NVD has 1,391)
        "cleaningCodeSha256": clean_manifest.get("cleaning_code_sha256"),
        "distribution": dists, "wasDerivedFrom": derived,
        "tables": [{"@id": f"{api_base}api/dataset/#{t}", "name": t, "rowCount": counts.get(t), "sha256": m["sha256"]}
                   for t, m in clean_manifest["tables"].items()],
    })


def snapshot_iri(content_id: str) -> str:
    """Identity of a snapshot = its content (first 16 hex digits of the content hash)."""
    return f"urn:threatgraph:snapshot:{content_id[:16]}"


def snapshot_node(m: dict) -> dict:
    """DCAT description of a snapshot folder (from its snapshot.json). ``wasRevisionOf`` links versions (PROV-O)."""
    iri = snapshot_iri(m["content_id"])
    prov = m.get("provenance") or {}
    return _clean({
        "@id": iri, "@type": "Dataset", "title": f"ThreatGraph-LD snapshot {m['label']}",
        "version": m["label"], "created": m["created_at_utc"], "contentId": m["content_id"],
        "wasRevisionOf": snapshot_iri(m["previous_content_id"]) if m.get("previous_content_id") else None,
        "rawManifestSha256": prov.get("raw_manifest_sha256"), "cleaningCodeSha256": prov.get("cleaning_code_sha256"),
        "tables": [{"@id": f"{iri}#{t}", "name": t, "rowCount": i["rows"], "sha256": i["sha256"]}
                   for t, i in m["tables"].items()]})


# ----------------------------------------------------------------------------- documents
def document(node: dict, context: dict | str = CONTEXT) -> dict:
    """A single node + the @context -> a complete JSON-LD document."""
    return {"@context": context, **node}


def graph_document(nodes: Iterable[dict], context: dict | str = CONTEXT, **page) -> dict:
    """A page of nodes. ``page`` may hold totalItems / nextPage / previousPage (None values are dropped)."""
    return {"@context": context, **_clean(page), "@graph": list(nodes)}


# ----------------------------------------------------------------------------- self-check
def terms_sharing_an_iri(context: dict = CONTEXT) -> dict[str, list[str]]:
    """Two context terms for the SAME IRI make compaction ambiguous (expand->compact may rename the key).
    Rule of this project: one term per IRI. Returns {iri: [terms]} for the violations (empty = OK)."""
    seen: dict[str, list[str]] = {}
    for term, d in context.items():
        if term.startswith("@") or isinstance(d, str) and d.endswith(("#", "/")):
            continue                                               # prefix declarations
        iri = d["@id"] if isinstance(d, dict) else d
        if iri.endswith("#") or iri in ("http://purl.org/dc/terms/",):
            continue
        seen.setdefault(iri, []).append(term)
    return {k: v for k, v in seen.items() if len(v) > 1}



def undefined_terms(obj: Any, context: dict = CONTEXT, _path: str = "$") -> list[str]:
    """Keys of the document that the @context does not define (JSON-LD would SILENTLY DROP them).
    Keys starting with '@' and compact IRIs (prefix:name with a known prefix) are fine."""
    problems: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.startswith("@"):
                pass
            elif k in context:
                pass
            elif ":" in k and k.split(":", 1)[0] in context:
                pass
            else:
                problems.append(f"{_path}.{k}")
            problems += undefined_terms(v, context, f"{_path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            problems += undefined_terms(v, context, f"{_path}[{i}]")
    return problems
