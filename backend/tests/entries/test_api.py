import io
from datetime import timedelta
from unittest.mock import Mock, patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test.utils import override_settings
from django.utils import timezone
from PIL import Image
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase, force_authenticate

from rola.contests.models import Contest, Theme
from rola.entries.api.views import FileViewSet, SubmissionViewSet
from rola.entries.models import Author, File, Submission
from tests.factories import create_user


def generate_photo():
    file = io.BytesIO()
    image = Image.new("RGB", (100, 100))
    image.save(file, "jpeg")
    file.seek(0)
    return file


class SubmissionViewSetTest(APITestCase):
    def setUp(self):
        self.creator = create_user("creator")
        self.user1 = create_user("user1")
        self.user2 = create_user("user2")

        today = timezone.now()
        tomorrow = today + timedelta(days=1)
        self.contest = Contest.objects.create(
            user=self.creator, title="Test contest", start_date=today, end_date=tomorrow
        )

        theme = Theme.objects.create(
            title="Test theme", contest=self.contest, n_photos=2
        )

        author1 = Author.objects.create(user=self.user1)
        author2 = Author.objects.create(user=self.user2)

        file_mock = SimpleUploadedFile("photo.jpg", b"fake photo")

        submission1 = Submission.objects.create(
            title="Submission 1",
            user=self.user1,
            author=author1,
            theme=theme,
        )
        submission2 = Submission.objects.create(
            title="Submission 2",
            user=self.user2,
            author=author2,
            theme=theme,
        )
        submission3 = Submission.objects.create(
            title="Submission 3",
            user=self.user2,
            author=author2,
            theme=theme,
        )

        # pk must be set to skip on-create procedure
        self.file1 = File.objects.create(
            pk=1, user=self.user1, submission=submission1, file=file_mock
        )
        self.file2 = File.objects.create(
            pk=2, user=self.user2, submission=submission2, file=file_mock
        )
        self.file3 = File.objects.create(
            pk=3, user=self.user2, submission=submission3, file=file_mock
        )

    def tearDown(self):
        self.file1.file.delete()
        self.file2.file.delete()
        self.file3.file.delete()

    def test_submission_queryset(self):
        viewset = SubmissionViewSet()
        viewset.action = "list"

        viewset.request = Mock(user=self.user2)
        self.assertEqual(len(viewset.get_queryset()), 2)

        self.contest.publish_date = timezone.now() - timedelta(days=1)
        self.contest.save()

        self.assertEqual(len(viewset.get_queryset()), 2)


@override_settings(ENTRIES_MAX_UPLOAD_SIZE=1024**2)
@override_settings(ENTRIES_MAX_UPLOAD_RESOLUTION=480)
class FileViewSetTest(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = create_user("user")

    def setUp(self):
        self.factory = APIRequestFactory()
        self.file_view = FileViewSet.as_view(
            {
                "post": "create",
            }
        )

    def get_upload_request(self):
        photo = generate_photo().read()
        headers = {"HTTP_CONTENT_DISPOSITION": "attachment; filename=test.jpg;"}
        return self.factory.post("", photo, content_type="image/jpeg", **headers)

    @patch("rola.entries.api.views.FileViewSet.create")
    def test_create_permissions(self, file_create_mock):
        file_create_mock.return_value = Response()
        request = self.factory.post("", format="json")

        # Public user.
        resp = self.file_view(request)
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(file_create_mock.call_count, 0)

        # Admin user.
        force_authenticate(request, self.user)
        resp = self.file_view(request)
        self.assertEqual(file_create_mock.call_count, 1)

    def test_create(self):
        request = self.get_upload_request()
        force_authenticate(request, self.user)

        resp = self.file_view(request)
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(File.objects.count(), 1)
        with File.objects.first().file.open("rb") as source:
            self.assertEqual(source.read(), generate_photo().read())

    @override_settings(ENTRIES_MAX_UPLOAD_SIZE=10)
    def test_create_exceed_size(self):
        request = self.get_upload_request()
        force_authenticate(request, self.user)

        resp = self.file_view(request)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data["file"][0], "Max size of file is 10B.")

    @override_settings(ENTRIES_MAX_UPLOAD_RESOLUTION=10)
    def test_create_exceed_res(self):
        request = self.get_upload_request()
        force_authenticate(request, self.user)

        resp = self.file_view(request)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data["file"][0], "Max photo resolution is 10px.")
