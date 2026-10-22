"""Shared helpers for the SPEC-0010 HTTP tests: a CSRF-enforcing browser and Admin fixtures."""

from django.contrib.sessions.models import Session
from rest_framework.test import APIClient

from apps.accounts.models import User
from apps.audit.context import audit_source
from apps.rbac import administration
from apps.rbac.principals import infrastructure_operator

OPERATOR = infrastructure_operator()
PASSWORD = "correct-horse-battery-staple"


class Browser:
    """Behaves like the frontend: real login, CSRF on, token read from the csrftoken cookie."""

    def __init__(self, address="203.0.113.10"):
        self.client = APIClient(enforce_csrf_checks=True, REMOTE_ADDR=address)

    def _csrf(self):
        if "csrftoken" not in self.client.cookies:
            self.client.get("/api/v1/auth/csrf/")
        return self.client.cookies["csrftoken"].value

    def get(self, path, params=None, **extra):
        return self.client.get(path, params, **extra)

    def send(self, method, path, data=None, *, csrf=True, raw=None, **extra):
        if csrf:
            extra["HTTP_X_CSRFTOKEN"] = self._csrf()
        if raw is not None:
            return getattr(self.client, method)(path, raw, content_type="application/json", **extra)
        return getattr(self.client, method)(path, data, format="json", **extra)

    def post(self, path, data=None, **kwargs):
        return self.send("post", path, {} if data is None else data, **kwargs)

    def patch(self, path, data=None, **kwargs):
        return self.send("patch", path, data, **kwargs)

    def login(self, username, password=PASSWORD):
        response = self.post("/api/v1/auth/login/", {"username": username, "password": password})
        assert response.status_code == 200, response.content
        return self

    def reauthenticate(self, password=PASSWORD):
        return self.post("/api/v1/auth/reauthenticate/", {"password": password})

    @property
    def session_key(self):
        return self.client.cookies["sessionid"].value

    def session_data(self):
        return Session.objects.get(session_key=self.session_key).get_decoded()


def make_user(username, password=PASSWORD):
    return User.objects.create_user(username=username, password=password)


def make_admin(username, password=PASSWORD):
    user = make_user(username, password)
    with audit_source("command"):
        administration.grant_admin(OPERATOR, user.pk)
    return user


def admin_browser(username="root", *, step_up=True):
    """A logged-in Admin browser, re-authenticated unless asked otherwise."""
    user = make_admin(username)
    browser = Browser().login(username)
    if step_up:
        assert browser.reauthenticate().status_code == 204
    return user, browser
