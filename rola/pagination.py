from rest_framework import pagination


class PageNumberPagination(pagination.PageNumberPagination):
    """Pagination class that enables arbitrary page sizes defined by the client."""

    page_size_query_param = 'page_size'
    max_page_size = 1000
