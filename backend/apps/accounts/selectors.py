"""Public identity queries; authorization never trusts loaded account flags."""

from apps.accounts.models import User


def users():
    return User.objects.all()
