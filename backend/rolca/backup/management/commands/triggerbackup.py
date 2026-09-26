""".. Ignore pydocstyle D400.

======================
Command: triggerbackup
======================
"""

import logging

from asgiref.sync import async_to_sync
from channels.layers import ChannelFull, get_channel_layer
from django.core.management.base import BaseCommand

from rolca.backup.models import FileBackup
from rolca.backup.protocol import CHANNEL_BACKUP, TYPE_FILE
from rolca.core.models import File

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Start backup via signal by django channels."""

    help = "Start backup via signal by django channels."

    def handle(self, *args, **options):
        """Command handle."""
        # Create missing backup objects.
        FileBackup.objects.bulk_create(
            [FileBackup(source=file) for file in File.objects.filter(filebackup=None)]
        )

        channel_layer = get_channel_layer()
        try:
            async_to_sync(channel_layer.send)(CHANNEL_BACKUP, {"type": TYPE_FILE})
        except ChannelFull:
            logger.warning("Cannot trigger backup because channel is full.")
