from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from rola.accounts.models import Token, User, token_digest


class TokenTestCase(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.USER_EMAIL = "user@example.com"
        cls.USER_PASSWORD = "p4ssWord123"
        cls.user = User.objects.create_user(
            email=cls.USER_EMAIL, password=cls.USER_PASSWORD, is_active=True
        )

    def test_login(self):
        response = self.client.post(
            reverse("login"),
            {"email": self.USER_EMAIL, "password": self.USER_PASSWORD},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.auth_tokens.count(), 1)
        self.assertCountEqual(response.data.keys(), ["token", "expires"])
        self.assertEqual(
            self.user.auth_tokens.get().digest, token_digest(response.data["token"])
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['token']}")
        accounts = self.client.get(reverse("user-list")).data["results"]
        self.assertEqual([account["id"] for account in accounts], [str(self.user.id)])

    def test_second_login(self):
        first = Token.objects.create_token(user=self.user)

        response = self.client.post(
            reverse("login"),
            {"email": self.USER_EMAIL, "password": self.USER_PASSWORD},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.auth_tokens.count(), 2)
        self.assertNotEqual(response.data["token"], first.key)
        self.assertCountEqual(
            self.user.auth_tokens.values_list("digest", flat=True),
            [token_digest(first.key), token_digest(response.data["token"])],
        )

    def test_login_inactive(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)

        response = self.client.post(
            reverse("login"),
            {"email": self.USER_EMAIL, "password": self.USER_PASSWORD},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["non_field_errors"][0],
            "Unable to log in with provided credentials.",
        )
        self.assertEqual(self.user.auth_tokens.count(), 0)
