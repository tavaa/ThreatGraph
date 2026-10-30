from rest_framework.pagination import PageNumberPagination


class StandardPagination(PageNumberPagination):
    """?page=N&page_size=M  (default 50, maximum 200: a client cannot ask for the whole table in one go)."""
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200
