from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from drf_user.models import Token, User


class TokenTestCase(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.USER_EMAIL = 'user@example.com'
        cls.USER_PASSWORD = 'p4ssWord123'
        cls.user = User.objects.create_user(
            email=cls.USER_EMAIL, password=cls.USER_PASSWORD, is_active=True
        )

    def test_login(self):
        response = self.client.post(
            reverse('login'),
            {'email': self.USER_EMAIL, 'password': self.USER_PASSWORD},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.auth_tokens.count(), 1)
        self.assertCountEqual(response.data.keys(), ['token', 'expires'])
        self.assertEqual(self.user.auth_tokens.first().key, response.data['token'])

    def test_second_login(self):
        Token.objects.create_token(user=self.user)

        response = self.client.post(
            reverse('login'),
            {'email': self.USER_EMAIL, 'password': self.USER_PASSWORD},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.auth_tokens.count(), 2)
        self.assertNotEqual(
            self.user.auth_tokens.all()[0].key, self.user.auth_tokens.all()[1].key
        )

    def test_login_inactive(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)

        response = self.client.post(
            reverse('login'),
            {'email': self.USER_EMAIL, 'password': self.USER_PASSWORD},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data['non_field_errors'][0],
            "Unable to log in with provided credentials.",
        )
        self.assertEqual(self.user.auth_tokens.count(), 0)

