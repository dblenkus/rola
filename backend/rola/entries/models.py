"""Store authors, submissions, submission sets and photographs."""

import logging
from functools import partial

from django.core.files.base import ContentFile
from django.db import models, transaction
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

from rola.common.models import BaseModel
from rola.contests.models import Contest, Theme
from rola.entries.photos import (
    create_thumbnail,
    generate_file_filename,
    generate_thumb_filename,
    strip_metadata,
    validate_image,
)

logger = logging.getLogger(__name__)


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

    submissions = models.ManyToManyField("entries.Submission")

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
            self.thumbnail = create_thumbnail(self.file)

        super().save(*args, **kwargs)

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

    date_of_birth = models.DateField(null=True, blank=True)

    school = models.CharField(max_length=100, null=True, blank=True)

    mentor = models.CharField(max_length=100, null=True, blank=True)

    club = models.CharField(max_length=100, null=True, blank=True)

    distinction = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        """Return string representation of Author object."""
        return f"{self.first_name} {self.last_name}"
