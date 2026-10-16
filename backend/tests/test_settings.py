"""Production settings must fail closed (SPEC-0001 SEC-01..SEC-04, SEC-12)."""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from django.conf import settings

BACKEND_DIR = Path(__file__).resolve().parent.parent

_DUMP_SETTINGS = """
import json, os, sys
os.environ["DJANGO_SETTINGS_MODULE"] = sys.argv[1]
from django.conf import settings
print(json.dumps({name: getattr(settings, name) for name in sys.argv[2:]}, default=str))
"""


def _prod_env(**overrides: str | None) -> dict[str, str]:
    env = {
        "PATH": os.environ["PATH"],
        "DJANGO_SECRET_KEY": secrets.token_urlsafe(64),
        "DJANGO_ALLOWED_HOSTS": "trilha.example.com",
        "POSTGRES_DB": "trilha",
        "POSTGRES_USER": "trilha",
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        "POSTGRES_HOST": "db",
        "REDIS_HOST": "redis",
        "REDIS_PASSWORD": secrets.token_urlsafe(24),
    }
    for name, value in overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _load_prod_settings(env: dict[str, str], *names: str) -> dict:
    result = _run(["-c", _DUMP_SETTINGS, "config.settings.prod", *names], env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_prod_debug_cannot_be_enabled_cwe_1188():
    loaded = _load_prod_settings(_prod_env(DJANGO_DEBUG="true"), "DEBUG")

    assert loaded["DEBUG"] is False


@pytest.mark.parametrize(
    "secret_key",
    [None, "too-short", "change-me-" + "x" * 60],
    ids=["missing", "too-short", "placeholder"],
)
def test_prod_settings_refuse_placeholder_secret_cwe_1188(secret_key):
    result = _run(
        ["-c", _DUMP_SETTINGS, "config.settings.prod", "DEBUG"],
        _prod_env(DJANGO_SECRET_KEY=secret_key),
    )

    assert result.returncode != 0
    assert "DJANGO_SECRET_KEY" in result.stderr
    if secret_key:
        assert secret_key not in result.stderr


def test_prod_settings_require_allowed_hosts():
    result = _run(
        ["-c", _DUMP_SETTINGS, "config.settings.prod", "DEBUG"],
        _prod_env(DJANGO_ALLOWED_HOSTS=None),
    )

    assert result.returncode != 0
    assert "DJANGO_ALLOWED_HOSTS" in result.stderr


def test_prod_settings_refuse_placeholder_database_password_cwe_1188():
    result = _run(
        ["-c", _DUMP_SETTINGS, "config.settings.prod", "DEBUG"],
        _prod_env(POSTGRES_PASSWORD="change-me-database-password"),
    )

    assert result.returncode != 0
    assert "POSTGRES_PASSWORD" in result.stderr


def test_prod_settings_pass_check_deploy():
    result = _run(
        ["manage.py", "check", "--deploy", "--fail-level", "WARNING"],
        _prod_env(DJANGO_SETTINGS_MODULE="config.settings.prod"),
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_prod_settings_refuse_placeholder_redis_password_cwe_1188():
    result = _run(
        ["-c", _DUMP_SETTINGS, "config.settings.prod", "DEBUG"],
        _prod_env(REDIS_PASSWORD="change-me-redis-password"),
    )

    assert result.returncode != 0
    assert "REDIS_PASSWORD" in result.stderr


def test_prod_cookie_flags():
    loaded = _load_prod_settings(
        _prod_env(),
        "SESSION_COOKIE_SECURE",
        "SESSION_COOKIE_HTTPONLY",
        "SESSION_COOKIE_SAMESITE",
        "SESSION_COOKIE_AGE",
        "CSRF_COOKIE_SECURE",
        "CSRF_COOKIE_SAMESITE",
    )

    assert loaded == {
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_AGE": 8 * 60 * 60,
        "CSRF_COOKIE_SECURE": True,
        "CSRF_COOKIE_SAMESITE": "Lax",
    }


def test_session_cookie_age_above_limit_is_rejected():
    result = _run(
        ["-c", _DUMP_SETTINGS, "config.settings.prod", "DEBUG"],
        _prod_env(DJANGO_SESSION_COOKIE_AGE=str(48 * 60 * 60)),
    )

    assert result.returncode != 0
    assert "DJANGO_SESSION_COOKIE_AGE" in result.stderr


def test_password_hashers_order():
    assert settings.PASSWORD_HASHERS[:2] == [
        "django.contrib.auth.hashers.Argon2PasswordHasher",
        "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    ]
