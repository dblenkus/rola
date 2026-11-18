from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase, force_authenticate

from rola.contests.api.views import ContestViewSet


class ContestApiTest(APITestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

        self.contest_list_view = ContestViewSet.as_view(
            {
                "get": "list",
                "post": "create",
            }
        )
        self.contest_detail_view = ContestViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        )

        self.user = MagicMock(spec=get_user_model(), is_superuser=False)
        self.super_user = MagicMock(spec=get_user_model(), is_superuser=True)

    @patch("rola.contests.api.views.ContestViewSet.create")
    def test_create_permissions(self, contest_create_mock):
        contest_create_mock.return_value = Response()
        request = self.factory.post("", {}, format="json")

        # public user
        resp = self.contest_list_view(request)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(contest_create_mock.call_count, 0)

        # normal user
        force_authenticate(request, self.user)
        resp = self.contest_list_view(request)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(contest_create_mock.call_count, 0)

        # admin user
        force_authenticate(request, self.super_user)
        resp = self.contest_list_view(request)
        self.assertEqual(contest_create_mock.call_count, 1)

    @patch("rola.contests.api.views.ContestViewSet.list")
    def test_get_list_permissions(self, contest_list_mock):
        contest_list_mock.return_value = Response()
        request = self.factory.get("", format="json")

        # public user
        self.contest_list_view(request)
        self.assertEqual(contest_list_mock.call_count, 1)
        contest_list_mock.reset_mock()

        contest_list_mock.reset_mock()

        # normal user
        force_authenticate(request, self.user)
        self.contest_list_view(request)
        self.assertEqual(contest_list_mock.call_count, 1)

    @patch("rola.contests.api.views.ContestViewSet.retrieve")
    def test_get_detail_permissions(self, contest_retrieve_mock):
        contest_retrieve_mock.return_value = Response()
        request = self.factory.get("", format="json")

        # public user
        self.contest_detail_view(request, pk=1)
        self.assertEqual(contest_retrieve_mock.call_count, 1)

        contest_retrieve_mock.reset_mock()

        # normal user
        force_authenticate(request, self.user)
        self.contest_detail_view(request, pk=1)
        self.assertEqual(contest_retrieve_mock.call_count, 1)

    @patch("rola.contests.api.views.ContestViewSet.update")
    def test_put_permissions(self, contest_update_mock):
        contest_update_mock.return_value = Response()
        request = self.factory.put("", {}, format="json")

        # public user
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(contest_update_mock.call_count, 0)

        # normal user
        force_authenticate(request, self.user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(contest_update_mock.call_count, 0)

        # admin user
        force_authenticate(request, self.super_user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(contest_update_mock.call_count, 1)

    @patch("rola.contests.api.views.ContestViewSet.partial_update")
    def test_patch_permissions(self, contest_update_mock):
        contest_update_mock.return_value = Response()
        request = self.factory.patch("", {}, format="json")

        # public user
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(contest_update_mock.call_count, 0)

        # normal user
        force_authenticate(request, self.user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(contest_update_mock.call_count, 0)

        # admin user
        force_authenticate(request, self.super_user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(contest_update_mock.call_count, 1)

    @patch("rola.contests.api.views.ContestViewSet.destroy")
    def test_delete_permissions(self, contest_destroy_mock):
        contest_destroy_mock.return_value = Response()
        request = self.factory.delete("", {}, format="json")

        # public user
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(contest_destroy_mock.call_count, 0)

        # normal user
        force_authenticate(request, self.user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(contest_destroy_mock.call_count, 0)

        # admin user
        force_authenticate(request, self.super_user)
        resp = self.contest_detail_view(request, pk=1)
        self.assertEqual(contest_destroy_mock.call_count, 1)
