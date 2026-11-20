import re
import time
from unittest.mock import Mock, patch
from urllib.parse import unquote

from django.core import mail
from django.db.models import F
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from rola.accounts.models import User
from rola.accounts.settings import accounts_settings
from rola.accounts.utils.signing import generate_activation_token, generate_reset_token


class RegistrationTest(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.USER_EMAIL = "user@example.com"
        cls.USER_PASSWORD = "pa55word!"
        cls.user = User.objects.create_user(
            first_name="Klemen",
            last_name="Krajnc",
            email=cls.USER_EMAIL,
            password=cls.USER_PASSWORD,
            is_active=True,
        )

        cls.post_data = {
            "first_name": "Janez",
            "last_name": "Novak",
            "email": "janez@example.com",
            "password": "p4ssWord123",
            "address": "Test Street 1",
            "city": "Ljubljana",
            "postal_code": "1000",
            "country": "SI",
        }

        cls.list_url = reverse("user-list")
        cls.activate_account_url = reverse("activation-list")

    def test_create_user(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.list_url, self.post_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

        user = User.objects.get(email=self.post_data["email"])
        self.assertTrue(user.check_password(self.post_data["password"]))
        self.assertFalse(user.is_active)

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Welcome", mail.outbox[0].subject)
        match = re.search(
            r"(?P<url>https?://.*\?token=(?P<token>.*))$", mail.outbox[0].body
        )
        token = unquote(match.group("token"))
        self.assertIn("/register/activate?", match.group("url"))

        response = self.client.post(
            self.activate_account_url, {"token": token}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    def test_expired_activation_token(self):
        self.user.is_active = False
        self.user.save()

        mocked_time = Mock()
        expires_seconds = accounts_settings.ACTIVATION_TOKEN_EXPIRES_SECONDS
        mocked_time.return_value = time.time() - expires_seconds.total_seconds()
        with patch("django.core.signing.time.time", mocked_time):
            token = generate_activation_token(self.user)

        response = self.client.post(
            self.activate_account_url,
            {"token": token},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_required_fields(self):
        post_data = self.post_data.copy()
        post_data.pop("first_name")
        response = self.client.post(
            self.list_url,
            post_data,
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["first_name"][0], "This field is required.")

        post_data = self.post_data.copy()
        post_data.pop("last_name")
        response = self.client.post(
            self.list_url,
            post_data,
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["last_name"][0], "This field is required.")

        post_data = self.post_data.copy()
        post_data.pop("email")
        response = self.client.post(
            self.list_url,
            post_data,
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["email"][0], "This field is required.")

        post_data = self.post_data.copy()
        post_data.pop("password")
        response = self.client.post(
            self.list_url,
            post_data,
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["password"][0], "This field is required.")


class ResetPasswordTest(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.USER_EMAIL = "user@example.com"
        cls.USER_PASSWORD = "pa55word!"
        cls.user = User.objects.create_user(
            email=cls.USER_EMAIL, password=cls.USER_PASSWORD, is_active=True
        )

        cls.request_reset_password_url = reverse("password-reset-request-list")
        cls.reset_password_url = reverse("password-reset-list")

    def test_reset_password(self):
        new_password = "n3wp4ss!"

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                self.request_reset_password_url,
                {"email": self.USER_EMAIL},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("password reset", mail.outbox[0].subject)
        match = re.search(
            r"(?P<url>https?://.*\?token=(?P<token>.*))$", mail.outbox[0].body
        )
        token = unquote(match.group("token"))
        self.assertIn("/password-reset?", match.group("url"))

        response = self.client.post(
            self.reset_password_url,
            {"token": token, "new_password": new_password},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_expired_token(self):
        mocked_time = Mock()
        mocked_time.return_value = (
            time.time() - accounts_settings.RESET_TOKEN_EXPIRES_SECONDS.total_seconds()
        )
        with patch("django.core.signing.time.time", mocked_time):
            token = generate_reset_token(self.user)

        response = self.client.post(
            self.reset_password_url,
            {"token": token, "new_password": "n3wp4ss!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["non_field_errors"][0], "Bad token.")

    def test_old_counter(self):
        token = generate_reset_token(self.user)

        self.user.password_reset_counter = F("password_reset_counter") + 1
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            {"token": token, "new_password": "n3wp4ss!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["non_field_errors"][0], "Bad token.")

    def test_inactive_user(self):
        token = generate_reset_token(self.user)

        self.user.is_active = False
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            {"token": token, "new_password": "n3wp4ss!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertTrue(self.user.check_password("n3wp4ss!"))
