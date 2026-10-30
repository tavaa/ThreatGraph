# Phase 4 — REST API, JSON-LD, client: design notes

Labels: [LITERATURE] supported by a source · [INFERENCE] own reasoning · [PROPOSAL] our choice · [UNCERTAIN] not verified.

## 1. What was built
| Piece | File | Idea |
|---|---|---|
| REST API (read-only) | `webapp/catalog/api_views.py`, `serializers.py`, `filters.py`, `pagination.py` | Django REST framework `ReadOnlyModelViewSet`, filters with django-filter, page size capped at 200 |
| JSON-LD | `src/threatgraph/jsonld.py` | pure functions: REST dictionary → JSON-LD node. One source, two formats |
| Content negotiation | `renderers.py`, `JsonLdMixin` | `Accept: application/ld+json` or `?format=jsonld` |
| Dataset metadata | `/api/dataset/` | DCAT `Dataset` + PROV `wasDerivedFrom` to the 4 pinned sources + hashes |
| Client | `src/threatgraph/api_client.py` | `requests` session, retry on GET only, follows `next` links, `ApiError` |

## 2. Decisions and trade-offs
| Decision [PROPOSAL] | Why | Alternative and its cost |
|---|---|---|
| JSON-LD built **from the REST dictionary** | the two formats cannot disagree; one place to fix | separate JSON-LD serializers: twice the code, can drift |
| `@id` = public IRI of the thing (NVD page, attack.mitre.org page, cwe.mitre.org page) | other graphs about the same CVE/technique merge with ours without mapping tables (FAIR F1, I3) | `@id` = our own API URL: simpler, but our data would never link to anyone else's |
| PKEV mapping = node of its own (`tg:Mapping`) | it has attributes (type, comments, evidence): it is an *association class* in UML, a reified node in RDF | plain triple CVE → technique: loses the attributes |
| Unknown value = key **omitted** in JSON-LD, `null` in JSON | in RDF absence = "not stated"; an empty string would be a false statement | `null` has no meaning in RDF |
| One context term per IRI | otherwise `expand → compact` may rename keys (found by the gate: `cveId`, `cweId`, `techniqueId` all mapped to `dcterms:identifier`) | aliases: fine for humans, ambiguous for machines |
| Reuse standard vocabularies where a good term exists (Dublin Core, DCAT, PROV, XSD); own `tg:` terms for the cyber domain | interoperability (FAIR I2) | invent everything: no interoperability |
| Read-only API, open (no authentication) | the data are open; no write path means no write bugs | authentication: needed only if we ever write |

## 3. Problems the gate found (and the fixes)
1. `page_size` had no effect (`page_size_query_param` was not set): clients got 50 rows whatever they asked → `StandardPagination`.
2. `?has_attack=perhaps` returned the **unfiltered** list with status 200 (django-filter ignores unknown booleans) → `StrictBooleanFilter` (400).
3. Several context terms pointed to the same IRI → round trip unstable → unique term per IRI + a check.
4. Two of my own tests were wrong (a `?format=` probe sent a contradicting `Accept` header; the merge test assumed a property that both documents carry). Fixed the tests, not the code.

## 4. Known limits
* `tg:` namespace `https://example.org/threatgraph/vocab#` is a placeholder; no ontology document is published [UNCERTAIN for real use].
* Mapping IRI `urn:threatgraph:pkev-mapping:<n>` = position in the pinned PKEV file: stable only for that commit.
* Several filters on the same many-valued relation are applied one after the other (`technique=T1190&mapping_type=primary_impact` = "has a mapping to T1190 AND has a primary-impact mapping", maybe two different mappings). Tested and documented, not changed.
* No SHACL shapes, no OpenAPI schema, no authentication/HTTPS/rate limit; `runserver` is not a production server. Latency numbers are single-client sanity values.

## 5. Exam questions (try to answer before reading the notes)
1. Why is the JSON-LD generated from the REST dictionary instead of from the models? What do you gain and lose?
2. What does `@context` do? What happens to a key that the context does not define, and how did we test for it?
3. Why is the `@id` of a CVE the NVD URL and not our API URL? What does that buy for FAIR (F1, I2, I3)?
4. A CVE has `attack: []`. What does it mean, and what would be wrong to conclude?
5. Difference between a REST filter returning 400 and returning an empty list: which one is right for `?severity=EXTREME`, and why?
6. Why must the API be checked against the CSV files and not against the database?
7. What is an N+1 query problem? Which Django tools avoid it here (`select_related`, `prefetch_related`, `annotate`)?
8. How would you add authentication or write access, and what in the design would have to change?
9. What are DCAT and PROV-O used for in `/api/dataset/`? Which FAIR principles does it serve (F2, R1.2)?
10. Why is `PkevMapping` a node and not an edge in the graph?
