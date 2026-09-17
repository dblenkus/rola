"""Rolca backup settings."""

from django.conf import settings

bucket_name = getattr(settings, 'BACKUP_AWS_BUCKET_NAME')
access_key_id = getattr(settings, 'BACKUP_AWS_ACCESS_KEY_ID')
secret_access_key = getattr(settings, 'BACKUP_AWS_SECRET_ACCESS_KEY')
