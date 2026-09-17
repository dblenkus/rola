""".. Ignore pydocstyle D400.

===============
Signal Handlers
===============

"""

import logging

from asgiref.sync import async_to_sync
from channels.layers import ChannelFull, get_channel_layer

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from rolca.backup.models import FileBackup
from rolca.backup.protocol import CHANNEL_BACKUP, TYPE_FILE
from rolca.core.models import File

logger = logging.getLogger(__name__)


def commit_signal(file_backup_pk):
    """Trigger a backup on a separate worker."""
    channel_layer = get_channel_layer()
    try:
        async_to_sync(channel_layer.send)(
            CHANNEL_BACKUP,
            {"type": TYPE_FILE, "file_backup_pk": file_backup_pk},
        )
    except ChannelFull:
        logger.warning("Cannot trigger backup because channel is full.")


@receiver(post_save, sender=File)
def backup_post_save_handler(sender, instance, created, **kwargs):
    """Trigger a backup after a new File is created."""
    if created:
        file_backup = FileBackup.objects.create(source=instance)
        transaction.on_commit(lambda: commit_signal(file_backup.pk))
