"""Upload queued files to the configured S3 backup bucket."""

import logging

import boto3
from botocore.exceptions import ClientError
from channels.consumer import SyncConsumer

from django.utils import timezone

from rolca.backup import settings
from rolca.backup.models import FileBackup

logger = logging.getLogger(__name__)


class BackupConsumer(SyncConsumer):
    """Consumer for backups."""

    def backup_file(self, message):
        """Process backup for ~`rolca.core.models.File` object."""
        queryset = FileBackup.objects.filter(done__isnull=True)

        file_backup_pk = message.get('file_backup_pk')
        if file_backup_pk:
            queryset = queryset.filter(pk=file_backup_pk)

        session = boto3.Session(
            aws_access_key_id=settings.access_key_id,
            aws_secret_access_key=settings.secret_access_key,
        )
        s3client = session.client("s3")

        for file_backup in queryset:
            file_name = file_backup.source.file.name
            with file_backup.source.file.file.open('rb') as fh:
                try:
                    s3client.upload_fileobj(fh, settings.bucket_name, file_name)
                except ClientError:
                    logger.exception("File backup failed.")
                    continue

            file_backup.done = timezone.now()
            file_backup.save()
