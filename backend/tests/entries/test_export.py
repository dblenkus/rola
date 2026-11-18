"""Export a contest's entries from the admin and the exportcontest command."""

import io
import os
import tracemalloc
import zipfile
from datetime import datetime, timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import CommandError, call_command
from django.test import Client
from django.urls import reverse
from django.utils.text import slugify
from PIL import Image

from rola.entries.models import File
from tests.factories import (
    PASSWORD,
    create_user,
    photo,
    submitted,
)

pytestmark = pytest.mark.django_db


def test_export_requires_organizer_and_includes_every_file(world):
    item = submitted(world)
    files = [photo(world.owner, "first.jpg"), photo(world.owner, "second.jpg")]
    item.files.add(*files)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    staff = create_user("staff")
    staff.is_staff = True
    staff.save()
    world.client.force_login(staff)
    assert world.client.get(url).status_code == 403
    world.client.force_login(world.admin)
    response = world.client.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.getvalue())) as archive:
        members = [name for name in archive.namelist() if not name.endswith("/")]
        assert len(members) == 2
        assert len(set(members)) == 2
        for name in members:
            assert Image.open(io.BytesIO(archive.read(name))).size == (800, 600)
            # Photographs carry the time of the download, in local time.
            written = datetime(*archive.getinfo(name).date_time)
            assert abs(written - datetime.now()) < timedelta(minutes=5)


def test_contest_admin_download_button_links_to_the_download(world):
    browser = Client()
    browser.force_login(world.admin)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    for page in (
        "/django-admin/contests/contest/",
        f"/django-admin/contests/contest/{world.contest.pk}/change/",
    ):
        response = browser.get(page)
        assert response.status_code == 200
        assert f'<a class="button" href="{url}">Download</a>' in response.text


def test_export_sends_a_non_staff_organizer_to_the_admin_login(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    world.contest.user = world.owner
    world.contest.save()
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    browser = Client()
    browser.force_login(world.owner)
    response = browser.get(url)
    assert response.status_code == 302
    assert response.headers["Location"] == f"{reverse('admin:login')}?next={url}"


def test_export_lets_a_staff_organizer_download_their_contest(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    organizer = create_user("organizer")
    organizer.is_staff = True
    organizer.save()
    world.contest.user = organizer
    world.contest.save()
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    browser = Client()
    browser.force_login(organizer)
    response = browser.get(url)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/x-zip-compressed"


def test_export_sends_a_logged_out_organizer_to_the_admin_login(world):
    item = submitted(world)
    item.files.add(photo(world.owner))
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    browser = Client()
    response = browser.get(url)
    login_url = f"{reverse('admin:login')}?next={url}"
    assert response.status_code == 302
    assert response.headers["Location"] == login_url
    response = browser.post(
        login_url, {"username": world.admin.email, "password": PASSWORD, "next": url}
    )
    assert response.status_code == 302
    assert response.headers["Location"] == url
    response = browser.get(url)
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/x-zip-compressed"


def test_export_builds_the_archive_without_holding_it_in_memory(world):
    noise = Image.frombytes("RGB", (1000, 1000), os.urandom(3_000_000))
    data = io.BytesIO()
    noise.save(data, "JPEG", quality=95)
    item = submitted(world)
    item.files.add(
        *[
            File.objects.create(
                user=world.owner,
                file=SimpleUploadedFile(
                    f"noise-{index}.jpg", data.getvalue(), content_type="image/jpeg"
                ),
            )
            for index in range(12)
        ]
    )
    world.client.force_login(world.admin)
    url = f"/django-admin/contests/contest/{world.contest.pk}/download/"
    # The first request imports and compiles modules, which tracing would count.
    world.client.get(url).getvalue()
    tracemalloc.start()
    try:
        response = world.client.get(url)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert response.status_code == 200
    size = int(response.headers["Content-Length"])
    assert size > 12 * len(data.getvalue())
    # An archive built in memory needs more than its own size.
    assert peak < size / 4
    assert response.headers["Content-Disposition"] == (
        f'attachment; filename="{slugify(world.contest.title)}.zip"'
    )
    content = response.getvalue()
    assert len(content) == size
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.testzip() is None
        assert len([name for name in archive.namelist() if name.endswith(".jpg")]) == 12


def test_export_command_writes_the_contest_archive(world, tmp_path):
    item = submitted(world)
    item.files.add(photo(world.owner, "first.jpg"), photo(world.owner, "second.jpg"))
    world.client.force_login(world.admin)
    response = world.client.get(
        f"/django-admin/contests/contest/{world.contest.pk}/download/"
    )
    assert response.status_code == 200
    exports = tmp_path / "exports"
    exports.mkdir()
    path = exports / "salon.zip"

    call_command("exportcontest", world.contest.pk, str(path))

    with (
        zipfile.ZipFile(io.BytesIO(response.getvalue())) as downloaded,
        zipfile.ZipFile(path) as exported,
    ):
        assert exported.testzip() is None
        assert exported.namelist() == downloaded.namelist()
        assert len([name for name in exported.namelist() if name.endswith(".jpg")]) == 2
        for name in downloaded.namelist():
            assert exported.read(name) == downloaded.read(name)

    # An existing file is neither overwritten nor removed.
    content = path.read_bytes()
    with pytest.raises(CommandError, match="already exists"):
        call_command("exportcontest", world.contest.pk, str(path))
    assert path.read_bytes() == content

    unknown = exports / "unknown.zip"
    with pytest.raises(CommandError, match="does not exist"):
        call_command("exportcontest", world.contest.pk + 1, str(unknown))
    assert not unknown.exists()

    # A photograph missing from storage fails the export without leaving part
    # of the archive behind.
    os.remove(item.files.first().file.path)
    failed = exports / "failed.zip"
    with pytest.raises(FileNotFoundError):
        call_command("exportcontest", world.contest.pk, str(failed))
    assert not failed.exists()
