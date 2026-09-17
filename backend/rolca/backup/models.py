""".. Ignore pydocstyle D400.

=============
Backup models
=============

.. autoclass:: rolca.backup.models.FileBackup
    :members:

"""

from django.db import models

from rolca.core.models import File


class FileBackup(models.Model):
    """Backup of files in ~`rolca.core.models.File` model."""

    source = models.ForeignKey(File, on_delete=models.CASCADE)

    done = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """Return string representation of FileBackup object."""
        return "Backup of {}".format(self.source)
