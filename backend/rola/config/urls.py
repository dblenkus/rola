"""Route the versioned API, the contest download and the Django admin."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from rola.accounts import views as user_views
from rola.contests.api import urls as contests_api_urls
from rola.entries.api import urls as entries_api_urls
from rola.entries.api.accounts import UserViewSet
from rola.judging.api import urls as judging_api_urls
from rola.payments.api import urls as payments_api_urls

router = SimpleRouter(trailing_slash=False)
router.register("user", UserViewSet, basename="user")

route_lists = [
    entries_api_urls.routeList,
    contests_api_urls.routeList,
    payments_api_urls.routeList,
    judging_api_urls.routeList,
]
for route_list in route_lists:
    for prefix, viewset in route_list:
        router.register(prefix, viewset, basename=prefix.replace("/", "-"))

urlpatterns = [
    path("django-admin/", admin.site.urls),
    path("api/v1/user/login", user_views.LoginView.as_view(), name="login"),
    path("api/v1/", include(router.urls)),
    path("core/", include("rola.entries.urls", namespace="entries")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
