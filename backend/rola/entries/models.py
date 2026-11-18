""".. Ignore pydocstyle D400.

==============
Entries models
==============

.. autoclass:: rola.entries.models.Author
    :members:

.. autoclass:: rola.entries.models.Submission
    :members:

.. autoclass:: rola.entries.models.File
    :members:

"""

import hashlib
import io
import logging
import os
import struct
import time
from functools import partial

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import models, transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _
from PIL import Image, ImageOps

from rola.common.models import BaseModel
from rola.contests.models import Contest, Theme
from rola.entries.images import strip_metadata

logger = logging.getLogger(__name__)


def _generate_filename(instance, filename, prefix):
    """Generate unique filename with given prefix."""
    md5 = hashlib.md5()
    md5.update(struct.pack("f", time.time()))
    was_closed = instance.file.closed
    try:
        if was_closed:
            instance.file.open("rb")
        for chunk in instance.file.chunks():
            md5.update(chunk)
    finally:
        if was_closed:
            instance.file.close()
    extension = os.path.splitext(filename)[1]
    return os.path.join(prefix, md5.hexdigest() + extension)


def generate_file_filename(instance, filename):
    """Generate filename for uploaded photo."""
    return _generate_filename(instance, filename, "photos")


def generate_thumb_filename(instance, filename):
    """Generate filename for thumbnails of uploaded photos."""
    return _generate_filename(instance, filename, "thumbs")


class SubmissionSet(BaseModel):
    """Model for organizing submissions."""

    class Meta:
        """SubmissionSet Meta options."""

        ordering = ["id"]
        verbose_name = _("submission set")
        verbose_name_plural = _("submission sets")
        constraints = [
            models.UniqueConstraint(
                fields=["user", "upload_key"],
                name="entries_submissionset_unique_upload_key",
            ),
        ]

    submissions = models.ManyToManyField("Submission")

    contest = models.ForeignKey(
        Contest, on_delete=models.CASCADE, related_name="submission_sets"
    )

    author = models.ForeignKey("Author", on_delete=models.CASCADE)

    #: client's key for the upload request that created the set, so that a
    #: repeated request returns this set instead of creating another one
    upload_key = models.UUIDField(null=True, blank=True, editable=False)

    def __str__(self):
        """Return string representation of SubmissionSet object."""

        first_submission = self.submissions.first()
        author = first_submission.author if first_submission else "/"
        return f"{self.submissions.count()} submissions by {author}"


class Submission(BaseModel):
    """Model for storing uploaded submissions."""

    class Meta:
        """Submission Meta options."""

        ordering = ["id"]
        verbose_name = _("submission")
        verbose_name_plural = _("submissions")

    title = models.CharField(_("Title"), max_length=100, null=True, blank=True)

    description = models.TextField(null=True, blank=True)

    author = models.ForeignKey("Author", on_delete=models.CASCADE)

    theme = models.ForeignKey(Theme, on_delete=models.PROTECT)

    def __str__(self):
        """Return string representation of Submission object."""
        return self.title or f"Submission {self.pk}"


def validate_image(file):
    """Validate the upload size, format and longest image edge.

    The photograph must be a JPEG file whose metadata can be stripped.
    """
    max_size = settings.ENTRIES_MAX_UPLOAD_SIZE
    if file.size > max_size:
        raise ValidationError(f"Max size of file is {max_size}B.")

    # Pillow reports a JPEG file that holds further pictures, as many
    # cameras write it, as MPO; stripping keeps only its first picture.
    if file.image.format not in ("JPEG", "MPO"):
        raise ValidationError("Photographs must be JPEG files.")

    max_res = settings.ENTRIES_MAX_UPLOAD_RESOLUTION
    if max(file.image.size) > max_res:
        raise ValidationError(f"Max photo resolution is {max_res}px.")

    file.seek(0)
    try:
        strip_metadata(file.read())
    except ValueError as error:
        raise ValidationError("The photograph is not a valid JPEG file.") from error
    finally:
        file.seek(0)


class File(BaseModel):
    """Model for storing uploaded images.

    Uploaded images can be stored prior to creating Submission
    instance. This way you can upload images while user is typing other
    data.Images are checked if meet size and format requirements before
    saving.

    """

    class Meta:
        """File Meta options."""

        ordering = ["id"]
        verbose_name = _("file")
        verbose_name_plural = _("files")

    submission = models.ForeignKey(
        Submission, related_name="files", null=True, on_delete=models.CASCADE
    )

    #: uploaded file
    file = models.ImageField(
        upload_to=generate_file_filename, validators=[validate_image]
    )

    #: thumbnail of uploaded file
    thumbnail = models.ImageField(upload_to=generate_thumb_filename)

    def save(self, *args, **kwargs):
        """Strip the photograph's metadata, add its thumbnail and save object.

        :raises ValueError: On create, if the photograph is not a well-formed
            JPEG file, which ``validate_image`` refuses.
        """
        if not self.pk:  # on create
            # Before the thumbnail and the generated name, which both derive
            # from the stored photograph.
            with self.file.open("rb") as upload:
                photograph = strip_metadata(upload.read())
            self.file = ContentFile(photograph, name=self.file.name)

            thumb = io.BytesIO()
            with Image.open(self.file) as image:
                # The thumbnail carries no EXIF data, so its pixels take the
                # orientation that viewers apply to the stored photograph.
                ImageOps.exif_transpose(image, in_place=True)
                image.thumbnail((400, 400), Image.Resampling.LANCZOS)
                image.save(
                    thumb, format="jpeg", quality=80, optimize=True, progressive=True
                )
            self.thumbnail = InMemoryUploadedFile(
                thumb, None, self.file.name, "image/jpeg", thumb.tell(), None
            )

        super().save(*args, **kwargs)

    def get_long_edge(self):
        """Return longer edge of the image."""
        return max(self.file.width, self.file.height)

    def __str__(self):
        """Return string representation of File object."""
        submission_title = self.submission.title if self.submission else "?"
        submission_id = self.submission.pk if self.submission else "?"
        return f"id: {self.pk}, filename: {self.file.name}, submission id: {submission_id}, submission title: {submission_title}"


def _delete_unreferenced_images(images):
    """Delete each stored image that no remaining file references.

    A storage error on one image does not stop the others. Once the delete
    has committed, no row names the image any more, so the log holds the
    only record of what is left in storage.
    """
    for image in images:
        referenced = models.Q(file=image.name) | models.Q(thumbnail=image.name)
        if File.objects.filter(referenced).exists():
            continue
        try:
            image.storage.delete(image.name)
        except Exception:
            logger.exception("Unable to delete stored image %s.", image.name)


@receiver(post_delete, sender=File)
def delete_stored_images(sender, instance, **kwargs):
    """Delete a removed file's photograph and thumbnail once the delete commits.

    Deleting a submission or a submission set removes its files by cascade,
    which calls no model ``delete`` method, so the cleanup listens for the
    signal. A rolled-back delete keeps the images.
    """
    images = [image for image in (instance.file, instance.thumbnail) if image.name]
    transaction.on_commit(partial(_delete_unreferenced_images, images), robust=True)


class Author(BaseModel):
    """Model for storing participents."""

    class Meta:
        """Author Meta options."""

        ordering = ["id"]
        verbose_name = _("author")
        verbose_name_plural = _("authors")

    #: ``Author``'s first name
    first_name = models.CharField(_("First name"), max_length=30)

    #: ``Author``'s last name
    last_name = models.CharField(_("Last name"), max_length=30)

    #: ``Author``'s email
    email = models.EmailField(_("Email"), null=True, blank=True)

    dob = models.DateField(null=True, blank=True)

    school = models.CharField(max_length=100, null=True, blank=True)

    mentor = models.CharField(max_length=100, null=True, blank=True)

    club = models.CharField(max_length=100, null=True, blank=True)

    distinction = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        """Return string representation of Author object."""
        return f"{self.first_name} {self.last_name}"
