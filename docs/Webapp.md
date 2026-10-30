# webapp/ (CONCEPTUAL – Phase 3/4, not created yet)

No Django code exists yet. Planned layout (created later with `django-admin startproject`):

```
webapp/
├── manage.py
├── threatgraph_site/          # settings, urls, wsgi
└── catalog/                   # the one app
    ├── models.py              # Vulnerability, KevEntry, NvdRecord, Cwe, Technique/Tactic, Mapping (association class), SourceFile/Snapshot (provenance)
    ├── serializers.py         # DRF serializers (JSON)
    ├── views.py  urls.py      # read-only REST endpoints + JSON-LD rendering
    ├── management/commands/   # load_clean_data (reads data/clean/)
    └── tests/
```

Design intent (to be justified in Phase 3): UML → Django ORM with an association class for CVE–technique mappings
(carries `mapping_type`, `comments`, `source`), provenance fields on every table, read-only API with filters and pagination.
