"""Local account and bearer-session helpers for NeuraLock."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import AuthSession, User


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 310_000
        )
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def issue_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
    ))
    db.commit()
    return token


def current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    raw_token = authorization[7:].strip()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    session = db.query(AuthSession).filter_by(token_hash=token_hash).first()
    now = datetime.now(timezone.utc)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid session.")
    expiry = session.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now:
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account is unavailable.")
    return user


def identity_for(user: User) -> dict:
    return {
        "user_id": user.id,
        "username": user.username,
        "organisation_id": user.organisation_id,
        "role": user.role,
    }
