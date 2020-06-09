from storages.backends.s3boto3 import S3Boto3Storage
from storages.utils import setting


class MediaStorage(S3Boto3Storage):
    bucket_name = setting('AWS_MEDIA_STORAGE_BUCKET_NAME')


class StaticStorage(S3Boto3Storage):
    bucket_name = setting('AWS_STATIC_STORAGE_BUCKET_NAME')
