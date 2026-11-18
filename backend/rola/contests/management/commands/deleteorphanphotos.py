"""Delete abandoned uploads and stored images that no upload references."""

from datetime import timedelta

from botocore.exceptions import ClientError
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from rola.contests.models import File

#: Younger uploads and stored images may belong to an upload in progress,
#: whose submission does not exist yet.
MINIMUM_AGE = timedelta(hours=24)

#: Folders that hold the uploaded photographs and their thumbnails. Contest
#: header images and anything else in the media storage live elsewhere.
FOLDERS = ("photos", "thumbs")


class Command(BaseCommand):
    """Delete uploads and stored images left behind by submissions."""

    help = (
        "Delete uploads that no submission holds and stored photographs and "
        "thumbnails that no upload references, once they are a day old."
    )

    def add_arguments(self, parser):
        """Accept a dry run."""
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Count what would be deleted and delete nothing.",
        )

    def handle(self, *args, **options):
        """Delete the unattached uploads, then the unreferenced images."""
        dry_run = options["dry_run"]
        cutoff = timezone.now() - MINIMUM_AGE
        verb = "to delete" if dry_run else "deleted"

        uploads = self._delete_unattached_uploads(cutoff, dry_run)
        self.stdout.write(f"Unattached uploads {verb}: {uploads}")

        # Runs after the uploads' delete has committed, so it also retries
        # their images if the delete signal could not remove them.
        images = self._delete_orphan_images(cutoff, dry_run)
        self.stdout.write(f"Unreferenced images {verb}: {images}")

    def _delete_unattached_uploads(self, cutoff, dry_run):
        """Delete uploads created before the cutoff that no submission holds.

        The delete signal removes their stored images once the delete commits.
        """
        with transaction.atomic():
            # The row locks keep a concurrent submission from attaching an
            # upload between this query and the delete.
            unattached = list(
                File.objects.select_for_update()
                .filter(submission__isnull=True, created__lt=cutoff)
                .order_by("pk")
                .values_list("pk", flat=True)
            )
            if not dry_run:
                File.objects.filter(pk__in=unattached).delete()
        return len(unattached)

    def _delete_orphan_images(self, cutoff, dry_run):
        """Delete stored images modified before the cutoff that no upload names."""
        storage = File._meta.get_field("file").storage
        referenced = {
            name
            for names in File.objects.values_list("file", "thumbnail")
            for name in names
        }
        orphans = [
            name
            for folder in FOLDERS
            for name in self._stored_names(storage, folder)
            if name not in referenced and self._modified_before(storage, name, cutoff)
        ]
        if not dry_run:
            for name in orphans:
                storage.delete(name)
        return len(orphans)

    def _modified_before(self, storage, name, cutoff):
        """Check whether a listed image was last modified before the cutoff.

        Deleting an upload removes its images after the listing, so an image
        that is already gone is left out. Any other storage error stops the
        command.
        """
        try:
            return storage.get_modified_time(name) < cutoff
        except FileNotFoundError:
            return False
        except ClientError as error:
            if error.response["ResponseMetadata"]["HTTPStatusCode"] == 404:
                return False
            raise

    def _stored_names(self, storage, folder):
        """Return the names of the files directly in a storage folder."""
        try:
            _, names = storage.listdir(folder)
        except FileNotFoundError:
            # A file system storage has no folder before the first upload.
            return []
        return [f"{folder}/{name}" for name in names]
