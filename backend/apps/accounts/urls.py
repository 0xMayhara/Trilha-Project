from django.urls import path

from apps.accounts import views

# No route takes a user identifier: every operation acts on request.user or a link (SEC-16).
urlpatterns = [
    path("csrf/", views.CsrfView.as_view(), name="auth-csrf"),
    path("login/", views.LoginView.as_view(), name="auth-login"),
    path("logout/", views.LogoutView.as_view(), name="auth-logout"),
    path("me/", views.MeView.as_view(), name="auth-me"),
    path("password/change/", views.PasswordChangeView.as_view(), name="auth-password-change"),
    path("password/set/", views.PasswordSetView.as_view(), name="auth-password-set"),
    path("reauthenticate/", views.ReauthenticateView.as_view(), name="auth-reauthenticate"),
]
