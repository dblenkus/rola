"""Rolca backup settings."""

from django.conf import settings

bucket_name = settings.BACKUP_AWS_BUCKET_NAME
access_key_id = settings.BACKUP_AWS_ACCESS_KEY_ID
secret_access_key = settings.BACKUP_AWS_SECRET_ACCESS_KEY
