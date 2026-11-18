"""Keep profile writes to the requesting account and its own address."""

import pytest
from django.urls import reverse

from rola.accounts.models import Location, User


@pytest.mark.parametrize("method", ["put", "patch"])
def test_profile_password_write_is_rejected(client, account, address, method):
    response = getattr(client, method)(
        reverse("user-detail", kwargs={"id": account.id}),
        {
            "password": "Replacement!73",
            "first_name": "Changed",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert set(response.data) == {"password"}
    account.refresh_from_db()
    assert account.check_password("Original!73")
    assert account.first_name is None
    assert not Location.objects.exists()


def test_profile_of_another_account_cannot_be_changed(client, account):
    other = User.objects.create_user(
        email="other@example.com", password="Original!73", is_active=True
    )
    response = client.patch(
        reverse("user-detail", kwargs={"id": other.id}), {"first_name": "Changed"}
    )
    assert response.status_code == 404
    other.refresh_from_db()
    assert other.first_name is None


def test_location_creation_and_partial_update_are_atomic(client, account, address):
    url = reverse("user-detail", kwargs={"id": account.id})
    response = client.get(url)
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == dict.fromkeys(address)
    assert "location" not in response.data

    response = client.patch(url, {"first_name": "Initial"})
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == dict.fromkeys(address)
    assert not Location.objects.exists()

    response = client.patch(url, {"city": "Ljubljana"})
    assert response.status_code == 400
    assert set(response.data) == {"address", "postal_code", "country"}
    assert Location.objects.count() == 0
    response = client.patch(url, address)
    assert response.status_code == 200
    assert {field: response.data[field] for field in address} == address
    response = client.patch(url, {"city": "Maribor", "first_name": "Changed"})
    assert response.status_code == 200
    updated_address = {**address, "city": "Maribor"}
    assert {field: response.data[field] for field in address} == updated_address
    account.refresh_from_db()
    assert {
        field: getattr(account.location, field) for field in address
    } == updated_address
    assert account.first_name == "Changed"
    assert Location.objects.count() == 1


@pytest.mark.parametrize("field", ["address", "city", "postal_code", "country"])
@pytest.mark.parametrize(
    ("value", "code"),
    [("x" * 101, "max_length"), (None, "null")],
    ids=["too_long", "null"],
)
def test_invalid_address_field_does_not_update_profile(
    client, account, address, field, value, code
):
    account.location = Location.objects.create(**address)
    account.save(update_fields=["location"])

    response = client.patch(
        reverse("user-detail", kwargs={"id": account.id}),
        {field: value, "first_name": "Changed"},
        format="json",
    )

    assert response.status_code == 400
    assert set(response.data) == {field}
    assert response.data[field][0].code == code
    account.refresh_from_db()
    assert account.first_name is None
    assert {field: getattr(account.location, field) for field in address} == address
    assert Location.objects.count() == 1


def test_deleting_an_account_deletes_its_address(client, account, address):
    account.location = Location.objects.create(**address)
    account.save(update_fields=["location"])
    other = User.objects.create_user(
        email="other@example.com", location=Location.objects.create(**address)
    )

    response = client.delete(reverse("user-detail", kwargs={"id": account.id}))

    assert response.status_code == 204
    assert not User.objects.filter(pk=account.pk).exists()
    assert list(Location.objects.values_list("pk", flat=True)) == [other.location_id]


def test_deleting_an_account_keeps_an_address_another_account_uses(
    client, account, address
):
    shared = Location.objects.create(**address)
    account.location = shared
    account.save(update_fields=["location"])
    other = User.objects.create_user(email="other@example.com", location=shared)

    response = client.delete(reverse("user-detail", kwargs={"id": account.id}))

    assert response.status_code == 204
    other.refresh_from_db()
    assert other.location == shared


def test_nullable_names_and_user_clean_are_safe(account):
    account.first_name = None
    account.last_name = None
    account.clean()
    assert account.get_full_name() == ""
    assert account.get_short_name() == ""


def test_malformed_account_id_does_not_reach_uuid_lookup(client):
    response = client.get("/api/v1/user/------------------------------------")
    assert response.status_code == 404


def test_profile_put_does_not_require_credentials(client, account, address):
    response = client.put(
        reverse("user-detail", kwargs={"id": account.id}),
        {"first_name": "Updated", "last_name": "Account", **address},
        format="json",
    )
    assert response.status_code == 200
    account.refresh_from_db()
    assert account.first_name == "Updated"
    assert account.location.city == address["city"]
    assert account.email == "person@example.com"
    assert account.check_password("Original!73")


@pytest.mark.parametrize("method", ["put", "patch"])
def test_profile_rejects_email_changes_atomically(client, account, address, method):
    response = getattr(client, method)(
        reverse("user-detail", kwargs={"id": account.id}),
        {
            "email": "changed@example.com",
            "first_name": "Changed",
            "last_name": "Account",
            **address,
        },
        format="json",
    )
    assert response.status_code == 400
    assert set(response.data) == {"email"}
    account.refresh_from_db()
    assert account.email == "person@example.com"
    assert account.first_name is None
    assert not Location.objects.exists()


def test_profile_accepts_unchanged_normalized_email(client, account):
    response = client.patch(
        reverse("user-detail", kwargs={"id": account.id}),
        {"email": "Person@Example.com", "first_name": "Updated"},
    )
    assert response.status_code == 200
    account.refresh_from_db()
    assert account.email == "person@example.com"
    assert account.first_name == "Updated"
