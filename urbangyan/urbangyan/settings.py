"""
Django settings for urbangyan project.

Generated by 'django-admin startproject' using Django 4.2.16.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from datetime import timedelta
from pathlib import Path
import os
from datetime import datetime, timedelta

from . import config
from .config import Config, SUPERUSER
from logging.handlers import TimedRotatingFileHandler
from dotenv import load_dotenv

load_dotenv()


SUPERUSER_NAME = SUPERUSER["username"]
SUPERUSER_PASSWORD = SUPERUSER["password"]

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Template and static files settings
TEMPLATES_DIR = os.path.join(BASE_DIR, "static/templates")
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]  # Folder for your static assets
STATIC_ROOT = os.path.join(
    BASE_DIR, "staticfiles"
)  # For collecting static files in production
MEDIA_ROOT = os.path.join(
    BASE_DIR, "media"
)  # Updated to use a standard media directory

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "your-default-secret-key"
)  # Load secret key from environment variable

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = (
    os.environ.get("DJANGO_DEBUG", "True") == "True"
)  # Load debug setting from environment variable

# ALLOWED_HOSTS setting
# Fetch DJANGO_ALLOWED_HOSTS from the environment or use default values
ALLOWED_HOSTS = os.environ.get(
    "DJANGO_ALLOWED_HOSTS",
    "127.0.0.1,localhost,d958-2401-4900-a006-34e5-7507-e79d-466c-64ce.ngrok-free.app",
).split(",")


# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "corsheaders",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "rest_framework",
    "drf_yasg",
    "crispy_forms",
    "rest_framework_simplejwt",
    "debug_toolbar",
    "ckeditor",
    "ckeditor_uploader",  # Add this line
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    'django.middleware.locale.LocaleMiddleware',  # Enables language switching
]

ROOT_URLCONF = "urbangyan.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATES_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "urbangyan.wsgi.application"

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

# Database settings from config.py
DATABASES = config.DATABASES
"""
DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',  # Use psycopg2 backend
            'NAME': 'urbangyan',  # Replace with your actual database name
            'USER': 'postgres',  # Replace with your actual database username
            'PASSWORD': os.getenv('DB_PASSWORD', 'tri123VENI!@#'),  # Default database password
            'HOST': '127.0.0.1',  # Set to 'localhost' if the DB is on the same machine
            'PORT': '5432',  # Default PostgreSQL port
        }
    }

"""
# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "/static/"  # Ensure static URL has a leading slash

# Media files
MEDIA_URL = "/media/"  # URL for media files
# Ensure MEDIA_ROOT is defined as mentioned above
MEDIA_ROOT = os.path.join(BASE_DIR, "media")  # Directory for uploaded media

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
JWT_SECRET_KEY = "MNBVCXZQWRY123POIU!@#"  # Your secret key to encode the JWT
JWT_ALGORITHM = "HS256"  # The algorithm to use for signing the token
# REST Framework settings
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        # Add other authentication classes if needed
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",  # Adjust based on your needs
    ),
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
}

# JWT settings
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}
AUTH_USER_MODEL = "core.User"

# settings.py

MEDIA_URL = "/media/"

MEDIA_ROOT = os.path.join(BASE_DIR, "media")


# config.py or settings.py
SUPERUSER_USERNAME = "Triveni"
SUPERUSER_PASSWORD = "tri123VENI!@#"
SUPERUSER_EMAIL = "triveni@example.com"

import logging

# Logging configuration

CORS_ALLOW_ALL_ORIGINS = (
    True  # Allow all origins for testing; consider refining this in production
)

import os
from logging.handlers import TimedRotatingFileHandler

# Define the log directory path
log_dir = os.path.join(BASE_DIR, "logs", "debug")

# Create the log directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)  # Creates the directory if it doesn't exist

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": os.path.join(log_dir, "debug.log"),
            "when": "midnight",  # Rotate at midnight each day
            "interval": 1,
            "backupCount": 10,  # Keep up to 5 backup log files
            "formatter": "verbose",
            "encoding": "utf-8",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["file"],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",  # Keep the default backend for other cases
)


CKEDITOR_UPLOAD_PATH = "uploads/"

CKEDITOR_CONFIGS = {
    "default": {
        "toolbar": "full",  # You can customize the toolbar here
        "height": 300,
        "width": "100%",
        "extraPlugins": ",".join(
            [
                "image2",  # Plugin for images
                "codesnippet",  # Plugin for code snippets
            ]
        ),
    },
}

CSRF_TRUSTED_ORIGINS = [
    "http://d958-2401-4900-a006-34e5-7507-e79d-466c-64ce.ngrok-free.app",
    "https://d958-2401-4900-a006-34e5-7507-e79d-466c-64ce.ngrok-free.app",  # For HTTPS
]

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "urbangyanin@gmail.com"  # Replace with your email
EMAIL_HOST_PASSWORD = "bgru zsro bvfu ivqi"  # Replace with your email password
DEFAULT_FROM_EMAIL = "Urban Gyan Admin"


from django.utils.translation import gettext_lazy as _

LANGUAGES = [
    ('en', _('English')),
    ('hi', _('Hindi')),
    ('es', _('Spanish')),
    ('fr', _('French')),
    ('de', _('German')),
]

LANGUAGE_CODE = 'en'  # Default Language
USE_I18N = True
USE_L10N = True
USE_TZ = True


LOCALE_PATHS = [
    BASE_DIR / 'locale',  # Location for translation files
]


SESSION_COOKIE_SAMESITE = 'None'  # For cross-site cookies
CSRF_COOKIE_SAMESITE = 'None'  # For CSRF cookies