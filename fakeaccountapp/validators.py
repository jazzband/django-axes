import re

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()


def normalize_username(username: str) -> str:
    """
    Zamienia znaki często używane do podszywania się pod inne konta
    oraz usuwa znaki specjalne.
    """

    username = username.lower().strip()

    replacements = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }

    for old, new in replacements.items():
        username = username.replace(old, new)

    # usunięcie wszystkiego poza literami i cyframi
    username = re.sub(r"[^a-z0-9]", "", username)

    return username


def validate_username_uniqueness(username: str):
    """
    Blokuje konta wyglądające identycznie po normalizacji.
    """

    normalized_new = normalize_username(username)

    existing_users = User.objects.values_list("username", flat=True)

    for existing_username in existing_users:
        normalized_existing = normalize_username(existing_username)

        if normalized_new == normalized_existing:
            raise ValidationError(
                f'Nazwa użytkownika jest zbyt podobna do istniejącego konta "{existing_username}".'
            )