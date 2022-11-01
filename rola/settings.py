"""
Django settings for rola project.

Generated by 'django-admin startproject' using Django 3.0.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

import os

from decouple import config, Csv


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEBUG = config('ROLA_DEBUG', default=False, cast=bool)

SECRET_KEY = config('ROLA_SECRET_KEY')

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='', cast=Csv())

AUTH_USER_MODEL = 'drf_user.User'

# Application definition

INSTALLED_APPS = [
    "channels",
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'django_filters',
    # 'rolca.backup',
    'rolca.core',
    'rolca.payment',
    'rolca.rating',
    'drf_user.apps.UserConfig',
    'storages',
    'utils',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'rola.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'rola.wsgi.application'


# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('ROLA_POSTGRESQL_NAME', default='rola'),
        'USER': config('ROLA_POSTGRESQL_USER', default='rola'),
        'HOST': config('ROLA_POSTGRESQL_HOST', default='postgresql'),
        'PORT': config('ROLA_POSTGRESQL_PORT', default=5432, cast=int),
        'CONN_MAX_AGE': None,  # Unlimited persistent connection.
        'OPTIONS': {'connect_timeout': 3,},
    }
}
database_password = config('ROLA_POSTGRESQL_PASSWORD', default=None)
if database_password:
    DATABASES['default']['PASSWORD'] = database_password
if config('ROLA_POSTGRESQL_SSLMODE', default=False, cast=bool):
    DATABASES['default']['OPTIONS']['sslmode'] = 'require'

redis_url = "{host}:{port}/{db}".format(
    host=config('ROLA_REDIS_HOST', default='redis'),
    port=config('ROLA_REDIS_PORT', default=6379, cast=int),
    db=config('ROLA_REDIS_DB', default=1, cast=int),
)
redis_password = config('ROLA_REDIS_PASSWORD', default=None)
if redis_password:
    redis_url = ":{}@{}".format(redis_password, redis_url)
redis_sslmode = config('ROLA_REDIS_SSLMODE', default=False, cast=bool)
redis_url = "{protocol}://{url}".format(
    protocol="rediss" if redis_sslmode else "redis", url=redis_url,
)
CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': redis_url,
        'OPTIONS': {'SOCKET_TIMEOUT': 3, 'SOCKET_CONNECT_TIMEOUT': 3,},
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# Password validation
# https://docs.djangoproject.com/en/dev/ref/settings/#auth-password-validators

if not config('ROLA_DISABLE_PASSWORD_VALIDATORS', default=False):
    AUTH_PASSWORD_VALIDATORS = [
        # {
        #     'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        # },
        {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
        {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
        {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    ]

# Django REST Framework

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': ['drf_user.authentication.TokenAuthentication'],
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticatedOrReadOnly',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.backends.DjangoFilterBackend',
        'rest_framework.filters.OrderingFilter',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rola.pagination.PageNumberPagination',
    'PAGE_SIZE': 500,
}

# Django channels.

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [redis_url]},
    },
}

ASGI_APPLICATION = "rola.routing.application"

# Internationalization
# https://docs.djangoproject.com/en/dev/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
if config('ROLA_USE_SES', default=False, cast=bool):
    EMAIL_BACKEND = 'django_smtp_ssl.SSLEmailBackend'
    DEFAULT_FROM_EMAIL = config('ROLA_DEFAULT_FROM_EMAIL')
    EMAIL_HOST = 'email-smtp.eu-west-1.amazonaws.com'
    EMAIL_PORT = 465
    EMAIL_HOST_USER = config('ROLA_SES_ACCESS_KEY_ID')
    EMAIL_HOST_PASSWORD = config('ROLA_SES_SECRET_ACCESS_KEY')
    EMAIL_USE_SSL = True

USE_X_FORWARDED_HOST = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/dev/howto/static-files/

if config('ROLA_USE_S3', default=False, cast=bool):
    # AWS settings.
    AWS_ACCESS_KEY_ID = config('ROLA_AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = config('ROLA_AWS_SECRET_ACCESS_KEY')
    AWS_S3_ENDPOINT_URL = config('ROLA_AWS_S3_ENDPOINT_URL')
    AWS_DEFAULT_ACL = None
    AWS_S3_OBJECT_PARAMETERS = {'CacheControl': 'max-age=86400'}
    # S3 static settings.
    STATICFILES_STORAGE = 'rola.backends.StaticStorage'
    AWS_STATIC_STORAGE_BUCKET_NAME = config('ROLA_AWS_STATIC_STORAGE_BUCKET_NAME')
    STATIC_URL = config('ROLA_STATIC_URL')
    # S3 media settings.
    DEFAULT_FILE_STORAGE = 'rola.backends.MediaStorage'
    AWS_MEDIA_STORAGE_BUCKET_NAME = config('ROLA_AWS_MEDIA_STORAGE_BUCKET_NAME')
    MEDIA_URL = config('ROLA_MEDIA_URL')
else:
    MEDIA_URL = '/media/'
    MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
    STATIC_URL = '/static2/'
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# CORS.

CORS_ORIGIN_REGEX_WHITELIST = [
    r"^(http:\/\/)?(localhost|127.0.0.1)(:\d+)$",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-disposition',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]


DATA_UPLOAD_MAX_MEMORY_SIZE = 10_485_760  # 10 MB

# Rolca.
ROLCA_MAX_UPLOAD_SIZE = 5_242_880  # 5MB
ROLCA_MAX_UPLOAD_RESOLUTION = 3500

BACKUP_AWS_BUCKET_NAME = config('ROLA_BACKUP_AWS_BUCKET_NAME', default='')
BACKUP_AWS_ACCESS_KEY_ID = config('ROLA_BACKUP_AWS_ACCESS_KEY_ID', default='')
BACKUP_AWS_SECRET_ACCESS_KEY = config('ROLA_BACKUP_AWS_SECRET_ACCESS_KEY', default='')


DRF_USER_APP_NAME = config('ROLA_APP_NAME', default="Rola")
