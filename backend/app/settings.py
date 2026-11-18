import os

ROLES = ("employee", "manager", "admin")


def current_identity() -> dict:
    organisation_id = os.getenv("NEURALOCK_ORGANISATION_ID", "local").strip() or "local"
    role = os.getenv("NEURALOCK_ROLE", "admin").strip().lower()
    if role not in ROLES:
        role = "employee"
    return {
        "organisation_id": organisation_id[:100],
        "role": role,
    }
