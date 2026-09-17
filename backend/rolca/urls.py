"""Main project's urls."""

from django.urls import include, path
from rest_framework import routers

from rolca.core.api import urls as core_api_urls
from rolca.payment.api import urls as payment_api_urls
from rolca.rating.api import urls as rating_api_urls

route_lists = [
    core_api_urls.routeList,
    payment_api_urls.routeList,
    rating_api_urls.routeList,
]

router = routers.DefaultRouter()
for route_list in route_lists:
    for prefix, viewset in route_list:
        router.register(prefix, viewset, basename=prefix.replace("/", "-"))


urlpatterns = [
    path("api/", include((router.urls, "rolca-core-api"), namespace="rolca-core-api")),
    path("core/", include("rolca.core.urls", namespace="rolca-core")),
]
