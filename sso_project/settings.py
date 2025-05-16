from pathlib import Path
import os



BASE_DIR = Path(__file__).resolve().parent.parent

from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-secret-override-me")
DEBUG = os.getenv("DJANGO_DEBUG", "True") == "True"
ALLOWED_HOSTS = ["*","127.0.0.1", "localhost", ".odx.kz"]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    "rest_framework",
    "authprovider",
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

ROOT_URLCONF = 'sso_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

WSGI_APPLICATION = 'sso_project.wsgi.application'

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "1000/day",
        "anon": "100/day",
    },
}


LANGUAGE_CODE = 'en'
TIME_ZONE = 'Asia/Aqtobe'
USE_I18N = True
USE_TZ = True

STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"  # куда collectstatic будет собирать

STATICFILES_DIRS = [
    BASE_DIR / "static",  # откуда collectstatic будет брать файлы
]
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS
CORS_ALLOW_ALL_ORIGINS = False

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:5500",
    "https://sso.odx.kz",
]
CORS_ALLOW_HEADERS = [
    "content-type",
    "authorization",
]

# SSO-прокси настройки
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'rsa-private.pem')

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "orleu")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "sso-proxy")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "6V9fRPpROX5Xuw51dDB9e5vLeWa7h3N7")
KEYCLOAK_ADMIN_CLIENT_ID = os.getenv("KEYCLOAK_ADMIN_CLIENT_ID", "sso-proxy")
KEYCLOAK_ADMIN_SECRET = os.getenv("KEYCLOAK_ADMIN_SECRET", "6V9fRPpROX5Xuw51dDB9e5vLeWa7h3N7")

OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://192.168.68.114:8000")

AUTH_CODE_REDIS_DB = 1  # или 0, если основной

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
SSO_REDIRECT_SPA = os.getenv("SSO_REDIRECT_SPA", "http://127.0.0.1:5500/sso-spa/")

ALLOW_CREATE_USERS = True  # или False — для прода или теста
ORLEU_API = "https://api.orleu-edu.kz/getiinwithroles"
ORLEU_API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiYXBpQG9ybGV1LWVkdS5reiIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IkFQSVVzZXIiLCJuYmYiOjE3NDU0NzAwMTYsImV4cCI6MTkwMzE1MDAxNiwiaXNzIjoiYXBpLm9ybGV1LWVkdS5reiIsImF1ZCI6Ik9ybGV1Q2xpZW50In0.2_4-YRu99ABkN-FFH3yAc489b_lBeChvG_MsIiKJLJ8"  # или в env


ALLOWED_CLIENTS = {
    "frontend-app": {
        "secret": "abc123xyz",
        "redirect_uris": [
            "http://localhost:3000/callback",
            "https://sso.odx.kz/callback"
        ]
    },
    "mobile-client": {
        "secret": None,
        "redirect_uris": [
            "com.odx.mobile://callback"
        ]
    },
    "sso-entry": {
        "secret": "sso-entry",
        "redirect_uris": [
            "http://localhost:8080/realms/orleu/broker/sso-entry/endpoint",
            "https://so.odx.kz/realms/orleu/broker/sso-entry/endpoint"
        ]
    },
    "sso": {
        "secret": "sso",
        "redirect_uris": [
            "https://so.odx.kz/realms/orleu/broker/sso/endpoint",
        ]
    },
}



NCANODE_URL = "http://nca.odx.kz/cms/verify"
NCANODE_BASIC_USER = "admin"
NCANODE_BASIC_PASS = "Alohomora999@"  # через .env лучше
