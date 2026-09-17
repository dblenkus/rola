""".. Ignore pydocstyle D400.

=============
Core API URLs
=============

The ``routList`` is ment to be included in ``urlpatterns`` with the
following code:

.. code-block:: python

    from rest_framework import routers

    from rolca.core.api import urls as core_api_urls

    route_lists = [
        core_api_urls.routeList,
        ...
    ]

    router = routers.DefaultRouter()
    for route_list in route_lists:
        for prefix, viewset in route_list:
            router.register(prefix, viewset, basename=prefix.replace('/', '-'))

For advanced configuration code can be accordingly changed to meet the
needs.

"""

from rolca.core.api.views import (
    AuthorViewSet,
    ContestViewSet,
    FileViewSet,
    InstitutionViewSet,
    SubmissionSetViewSet,
    SubmissionViewSet,
)

routeList = (
    (r"author", AuthorViewSet),
    (r"file", FileViewSet),
    (r"submission", SubmissionViewSet),
    (r"submissionset", SubmissionSetViewSet),
    (r"contest", ContestViewSet),
    (r"institution", InstitutionViewSet),
)
