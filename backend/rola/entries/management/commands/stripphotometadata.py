"""Strip identifying metadata from stored photographs."""

import os
import shutil
import tempfile

from django.core.files.storage import FileSystemStorage
from django.core.management.base import BaseCommand

from rola.entries.models import File
from rola.entries.photos import strip_metadata


class Command(BaseCommand):
    """Rewrite stored photographs without their identifying metadata."""

    help = (
        "Rewrite every stored photograph and thumbnail without the metadata "
        "that could identify its author or place, under the same name. Images "
        "without such metadata, files that are not valid JPEG photographs and "
        "images that are not in storage stay as they are, so the command can "
        "run again."
    )

    def handle(self, *args, **options):
        """Strip each photograph and thumbnail that an upload references."""
        storage = File._meta.get_field("file").storage
        rewritten = unchanged = invalid = missing = 0
        # Thumbnails made before uploads were stripped carry the comment of
        # their photograph.
        names = sorted(
            {
                name
                for names in File.objects.values_list("file", "thumbnail")
                for name in names
                if name
            }
        )
        for name in names:
            # Only a missing image is skipped; any other storage error,
            # such as a denied read, stops the command.
            try:
                with storage.open(name, "rb") as source:
                    data = source.read()
            except FileNotFoundError:
                self.stdout.write(f"Not in storage, left unchanged: {name}")
                missing += 1
                continue
            try:
                stripped = strip_metadata(data)
            except ValueError:
                self.stdout.write(f"Not a valid JPEG file, left unchanged: {name}")
                invalid += 1
                continue
            if stripped == data:
                unchanged += 1
                continue
            self._overwrite(storage, name, stripped)
            rewritten += 1

        self.stdout.write(f"Photographs and thumbnails rewritten: {rewritten}")
        self.stdout.write(
            f"Photographs and thumbnails already without metadata: {unchanged}"
        )
        self.stdout.write(f"Files that are not valid JPEG photographs: {invalid}")
        self.stdout.write(f"Files that are not in storage: {missing}")

    def _overwrite(self, storage, name, data):
        """Replace a stored file, keeping its name, so that no row changes.

        A reader sees either the old or the new photograph, never part of one.
        """
        if isinstance(storage, FileSystemStorage):
            path = storage.path(name)
            # Leaving the block deletes the temporary file if it was not moved.
            with tempfile.NamedTemporaryFile(
                dir=os.path.dirname(path), delete_on_close=False
            ) as temporary:
                temporary.write(data)
                temporary.close()
                # The temporary file is readable by its owner only.
                shutil.copymode(path, temporary.name)
                os.replace(temporary.name, path)
        else:
            # Writing to an open object keeps the name, which saving would
            # change, because the media storage never overwrites. S3 replaces
            # the object only once the upload is complete.
            with storage.open(name, "wb") as target:
                target.write(data)
