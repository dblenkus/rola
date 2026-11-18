"""Route the versioned API and the Django admin."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path
from rest_framework.routers import SimpleRouter

from rola.accounts.api import routes as accounts_routes
from rola.contests.api import routes as contests_routes
from rola.entries.api import routes as entries_routes
from rola.entries.api.accounts import UserViewSet
from rola.judging.api import routes as judging_routes
from rola.payments.api import routes as payments_routes

router = SimpleRouter(trailing_slash=False)
accounts_routes.register(router, UserViewSet)
entries_routes.register(router)
contests_routes.register(router)
payments_routes.register(router)
judging_routes.register(router)

urlpatterns: list[URLPattern | URLResolver] = [
    path("django-admin/", admin.site.urls),
    path("api/v1/", include(accounts_routes.urlpatterns)),
    path("api/v1/", include(router.urls)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
