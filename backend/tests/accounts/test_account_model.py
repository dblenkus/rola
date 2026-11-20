"""Keep account names and addresses consistent when accounts change or go."""

from rola.accounts.models import Location, User


def test_nullable_names_and_user_clean_are_safe(account):
    account.first_name = None
    account.last_name = None
    account.clean()
    assert account.get_full_name() == ""
    assert account.get_short_name() == ""


def test_deleting_an_account_deletes_its_address(account, address):
    account.location = Location.objects.create(**address)
    account.save(update_fields=["location"])
    other = User.objects.create_user(
        email="other@example.com", location=Location.objects.create(**address)
    )

    account.delete()

    assert not User.objects.filter(pk=account.pk).exists()
    assert list(Location.objects.values_list("pk", flat=True)) == [other.location_id]


def test_deleting_an_account_keeps_an_address_another_account_uses(account, address):
    shared = Location.objects.create(**address)
    account.location = shared
    account.save(update_fields=["location"])
    other = User.objects.create_user(email="other@example.com", location=shared)

    account.delete()

    other.refresh_from_db()
    assert other.location == shared
