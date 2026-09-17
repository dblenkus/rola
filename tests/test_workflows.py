"""Regression tests for public APIs using the host's custom user contract."""

import io
import zipfile
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from PIL import Image

from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from rest_framework.test import APIClient

from rolca.core.models import (
    Author,
    Contest,
    File,
    Institution,
    Submission,
    SubmissionSet,
    Theme,
)
from tests.userapp.models import Email, User

pytestmark = pytest.mark.django_db


@pytest.fixture
def world():
    owner = User.objects.create_user(username='owner', email='owner@example.org')
    other = User.objects.create_user(username='other', email='other@example.org')
    admin = User.objects.create_superuser(
        username='admin', email='admin@example.org', password='secret'
    )
    now = timezone.now()
    contest = Contest.objects.create(
        user=admin,
        title='Salon',
        start_date=now - timedelta(days=1),
        end_date=now + timedelta(days=1),
        publish_date=now + timedelta(days=2),
    )
    theme = Theme.objects.create(contest=contest, title='Nature', n_photos=4)
    author = Author.objects.create(
        user=owner, first_name='Alice', last_name='Photographer'
    )
    other_author = Author.objects.create(user=other, first_name='Other')
    client = APIClient()
    client.force_authenticate(owner)
    return SimpleNamespace(
        owner=owner,
        other=other,
        admin=admin,
        contest=contest,
        theme=theme,
        author=author,
        other_author=other_author,
        client=client,
    )


def photo(user, name='photo.jpg'):
    data = io.BytesIO()
    Image.new('RGB', (800, 600), 'red').save(data, 'JPEG')
    return File.objects.create(
        user=user,
        file=SimpleUploadedFile(name, data.getvalue(), content_type='image/jpeg'),
    )


def payload(world, **changes):
    result = {
        'title': 'Photo',
        'theme': world.theme.pk,
        'author': {'id': world.author.pk},
        'files': [{'id': photo(world.owner).pk}],
    }
    result.update(changes)
    return result


def submitted(world, **changes):
    data = dict(
        user=world.owner, title='Original', theme=world.theme, author=world.author
    )
    data.update(changes)
    return Submission.objects.create(**data)


def test_author_list_is_scoped_to_requesting_user(world):
    response = world.client.get('/api/author/')
    assert response.status_code == 200
    assert [item['id'] for item in response.data] == [world.author.pk]


@pytest.mark.parametrize('batch', [False, True])
def test_submission_creates_set_and_sends_one_confirmation_after_commit(
    world, batch, mailoutbox, django_capture_on_commit_callbacks
):
    world.contest.confirmation_email = Email.objects.create(
        subject='Thank you', body='Submitted'
    )
    world.contest.save()
    data = payload(world)
    if batch:
        data = [data, payload(world)]
    with django_capture_on_commit_callbacks(execute=True):
        response = world.client.post('/api/submission/', data, format='json')
        assert not mailoutbox
    assert response.status_code == 201, response.data
    assert isinstance(response.data, list) == batch
    group = SubmissionSet.objects.get()
    assert group.author == world.author
    assert group.contest == world.contest
    assert group.user == world.owner
    assert group.submissions.count() == (2 if batch else 1)
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == [world.owner.email]


@pytest.mark.parametrize(
    'case',
    [
        'empty',
        'unknown_author',
        'other_author',
        'unknown_file',
        'other_file',
        'duplicate_files',
        'attached_file',
        'mixed_contests',
        'mixed_authors',
        'reused_batch_file',
    ],
)
def test_invalid_submission_leaves_no_partial_records(world, case):
    data = payload(world)
    if case == 'empty':
        data = []
    elif case == 'unknown_author':
        data['author'] = {'id': 999999}
    elif case == 'other_author':
        data['author'] = {'id': world.other_author.pk}
    elif case == 'unknown_file':
        data['files'] = [{'id': 999999}]
    elif case == 'other_file':
        data['files'] = [{'id': photo(world.other).pk}]
    elif case == 'duplicate_files':
        data['files'] *= 2
    elif case == 'attached_file':
        existing = submitted(world)
        File.objects.filter(pk=data['files'][0]['id']).update(submission=existing)
    elif case == 'mixed_contests':
        contest = Contest.objects.create(
            title='Second',
            start_date=world.contest.start_date,
            end_date=world.contest.end_date,
        )
        theme = Theme.objects.create(title='Second', contest=contest, n_photos=4)
        data = [data, payload(world, theme=theme.pk)]
    elif case == 'mixed_authors':
        another = Author.objects.create(user=world.owner, first_name='Another')
        data = [data, payload(world, author={'id': another.pk})]
    elif case == 'reused_batch_file':
        data = [data, dict(data)]
    before = Submission.objects.count()
    response = world.client.post('/api/submission/', data, format='json')
    assert response.status_code == 400, response.data
    assert Submission.objects.count() == before
    assert SubmissionSet.objects.count() == 0


def test_submission_database_failure_rolls_back_files_and_records(
    world, django_capture_on_commit_callbacks
):
    data = payload(world)
    with django_capture_on_commit_callbacks(execute=True) as callbacks:
        with patch(
            'rolca.core.api.views.SubmissionSet.objects.create',
            side_effect=RuntimeError('database failure'),
        ):
            with pytest.raises(RuntimeError, match='database failure'):
                world.client.post('/api/submission/', data, format='json')
    assert not callbacks
    assert not Submission.objects.exists()
    assert File.objects.get(pk=data['files'][0]['id']).submission_id is None


@pytest.mark.parametrize('method', ['put', 'patch', 'delete'])
def test_published_foreign_submission_cannot_be_modified(world, method):
    world.contest.publish_date = timezone.now() - timedelta(hours=1)
    world.contest.save()
    item = submitted(world, user=world.other, author=world.other_author)
    response = getattr(world.client, method)(
        f'/api/submission/{item.pk}/', {'title': 'Changed'}, format='json'
    )
    assert response.status_code == 403
    item.refresh_from_db()
    assert item.title == 'Original'
    assert item.user == world.other


def test_owner_can_patch_submission_and_replace_own_files(world):
    item = submitted(world)
    old = photo(world.owner)
    old.submission = item
    old.save()
    new = photo(world.owner)
    response = world.client.patch(
        f'/api/submission/{item.pk}/',
        {'title': 'Edited', 'files': [{'id': new.pk}]},
        format='json',
    )
    assert response.status_code == 200, response.data
    item.refresh_from_db()
    old.refresh_from_db()
    assert item.title == 'Edited'
    assert item.user == world.owner
    assert list(item.files.values_list('pk', flat=True)) == [new.pk]
    assert old.submission_id is None


def test_submission_cannot_change_contest_or_author_after_grouping(world):
    response = world.client.post('/api/submission/', payload(world), format='json')
    assert response.status_code == 201
    author = Author.objects.create(user=world.owner, first_name='Another')
    response = world.client.patch(
        f"/api/submission/{response.data['id']}/",
        {'author': {'id': author.pk}},
        format='json',
    )
    assert response.status_code == 400


def test_owner_cannot_change_published_submission(world):
    item = submitted(world)
    world.contest.publish_date = timezone.now() - timedelta(seconds=1)
    world.contest.save()
    assert (
        world.client.patch(
            f'/api/submission/{item.pk}/', {'title': 'Late'}, format='json'
        ).status_code
        == 403
    )


def test_contest_and_institution_filters_are_applied(world):
    Contest.objects.create(
        title='Past',
        start_date=timezone.now() - timedelta(days=4),
        end_date=timezone.now() - timedelta(days=2),
    )
    response = world.client.get('/api/contest/', {'is_active': 'true'})
    assert [item['id'] for item in response.data] == [world.contest.pk]
    desired = Institution.objects.create(kind=1, name='School')
    Institution.objects.create(kind=1, name='Elsewhere')
    assert [
        item['id']
        for item in world.client.get('/api/institution/', {'name': 'School'}).data
    ] == [desired.pk]


def test_submission_and_set_filters_are_applied(world):
    item = submitted(world)
    group = SubmissionSet.objects.create(
        user=world.owner, author=world.author, contest=world.contest
    )
    group.submissions.add(item)
    assert world.client.get('/api/submission/', {'contest': 999999}).data == []
    other_contest = Contest.objects.create(
        title='Empty',
        start_date=world.contest.start_date,
        end_date=world.contest.end_date,
    )
    assert (
        world.client.get('/api/submissionset/', {'contest': other_contest.pk}).data
        == []
    )


def test_export_requires_organizer_and_includes_every_file(world):
    item = submitted(world)
    files = [photo(world.owner, 'first.jpg'), photo(world.owner, 'second.jpg')]
    item.files.add(*files)
    url = f'/core/contest/{world.contest.pk}/download'
    world.client.force_login(world.owner)
    assert world.client.get(url).status_code == 403
    world.client.force_login(world.admin)
    response = world.client.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        members = [name for name in archive.namelist() if not name.endswith('/')]
        assert len(members) == 2
        assert len(set(members)) == 2
        for name in members:
            assert Image.open(io.BytesIO(archive.read(name))).size == (800, 600)
