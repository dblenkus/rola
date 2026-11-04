"""Route the versioned API, the contest download and the Django admin."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import SimpleRouter

from drf_user import views as user_views
from rolca.urls import route_lists

router = SimpleRouter(trailing_slash=False)
router.register(r"user", user_views.UserViewSet)

for route_list in route_lists:
    for prefix, viewset in route_list:
        router.register(prefix, viewset)

urlpatterns = [
    path("django-admin/", admin.site.urls),
    path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path("api/v1/user/login", user_views.LoginView.as_view(), name="login"),
    path("api/v1/", include(router.urls)),
    path("core/", include("rolca.core.urls", namespace="rolca-core")),
    path("register/activate", user_views.activate_user_view, name="activate-user"),
    path("password-reset", user_views.password_reset_view, name="password-reset"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
