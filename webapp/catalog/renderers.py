from rest_framework.renderers import JSONRenderer


class JsonLdRenderer(JSONRenderer):
    """Same bytes as the JSON renderer, different media type: ``Accept: application/ld+json`` or ``?format=jsonld``
    (or the suffix ``.jsonld``). The JSON-LD structure itself is built in the views (src/threatgraph/jsonld.py)."""
    media_type = "application/ld+json"
    format = "jsonld"
