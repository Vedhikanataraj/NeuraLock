
from datetime import datetime, timezone
from sqlalchemy import Boolean, JSON, ForeignKey
from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False)
    risk_level = Column(String(20), nullable=False)
    action_taken = Column(String(50), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    organisation_id = Column(String(100), nullable=True, index=True)
class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"

    id = Column(Integer, primary_key=True, index=True)
    organisation_id = Column(String(100), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    allowed_roles = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    organisation_id = Column(String(100), nullable=True, index=True)


class ChatTurn(Base):
    __tablename__ = "chat_turns"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, nullable=False, index=True)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    action = Column(String(50), nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    password_hash = Column(String(300), nullable=False)
    organisation_id = Column(String(100), nullable=False, index=True)
    role = Column(String(20), nullable=False, default="employee")
    is_active = Column(Boolean, nullable=False, default=True)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
