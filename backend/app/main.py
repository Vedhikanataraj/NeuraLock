from pathlib import Path
from collections import defaultdict, deque
from time import monotonic
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.chatbot import decide_next_action
from app.db import Base, engine, get_db
from app.models import AuthSession, ChatTurn, Conversation, KnowledgeDocument, SecurityEvent, User
from app.auth import current_user, hash_password, identity_for, issue_session, verify_password

Base.metadata.create_all(bind=engine)
with engine.begin() as connection:
    # Lightweight additive migration for databases created by earlier prototypes.
    from sqlalchemy import inspect
    existing = inspect(engine)
    for table, column, declaration in (
        ("conversations", "user_id", "INTEGER REFERENCES users(id)"),
        ("conversations", "organisation_id", "VARCHAR(100)"),
        ("security_events", "user_id", "INTEGER REFERENCES users(id)"),
        ("security_events", "organisation_id", "VARCHAR(100)"),
        ("knowledge_documents", "created_by", "INTEGER REFERENCES users(id)"),
    ):
        if table in existing.get_table_names() and column not in {
            item["name"] for item in existing.get_columns(table)
        }:
            connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
    # Normalize legacy free-form organisation names once while preserving each
    # organisation's membership across all records.
    organisation_tables = ("users", "knowledge_documents", "conversations", "security_events")
    organisations = set()
    for table in organisation_tables:
        if table in existing.get_table_names() and "organisation_id" in {
            item["name"] for item in existing.get_columns(table)
        }:
            organisations.update(
                row[0] for row in connection.exec_driver_sql(
                    f"SELECT DISTINCT organisation_id FROM {table} WHERE organisation_id IS NOT NULL"
                ).fetchall()
            )
    valid_ids = {org_id for org_id in organisations if isinstance(org_id, str) and __import__("re").fullmatch(r"NL[0-9]{4}", org_id)}
    next_number = 1
    for old_id in sorted(org_id for org_id in organisations if org_id not in valid_ids):
        while f"NL{next_number:04d}" in valid_ids and next_number <= 9999:
            next_number += 1
        if next_number > 9999:
            raise RuntimeError("NeuraLock supports at most 9,999 organisation IDs.")
        new_id = f"NL{next_number:04d}"
        for table in organisation_tables:
            if table in existing.get_table_names() and "organisation_id" in {
                item["name"] for item in existing.get_columns(table)
            }:
                connection.exec_driver_sql(
                    f"UPDATE {table} SET organisation_id = ? WHERE organisation_id = ?",
                    (new_id, old_id),
                )
        valid_ids.add(new_id)
        next_number += 1

app = FastAPI(
    title="NeuraLock",
    description="Local AI Security Gateway",
    version="0.4.0",
)

RoleName = Literal["employee", "manager", "admin"]


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=5000)
    conversation_id: int | None = None


class DocumentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=20000)
    allowed_roles: list[RoleName]


class DocumentUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    content: str | None = Field(default=None, min_length=1, max_length=20000)
    allowed_roles: list[RoleName] | None = None
    is_active: bool | None = None


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=256)
    organisation_id: str = Field(default="NL0001", pattern=r"^NL[0-9]{4}$")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12, max_length=256)
    role: RoleName = "employee"


def _require_admin(identity: dict) -> None:
    if identity["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only the admin identity can change documents.",
        )


def _with_admin(roles: list[str]) -> list[str]:
    return sorted(set(roles) | {"admin"})


def _document_in_org(db: Session, document_id: int, organisation_id: str):
    document = db.get(KnowledgeDocument, document_id)
    if document is None or document.organisation_id != organisation_id:
        return None
    return document


def _allowed_documents(db: Session, identity: dict) -> list[KnowledgeDocument]:
    documents = (
        db.query(KnowledgeDocument)
        .filter(
            KnowledgeDocument.organisation_id == identity["organisation_id"],
            KnowledgeDocument.is_active.is_(True),
        )
        .order_by(KnowledgeDocument.id.asc())
        .all()
    )
    return [
        document
        for document in documents
        if identity["role"] in (document.allowed_roles or [])
    ]


def _select_relevant_documents(message: str, documents: list[KnowledgeDocument]) -> list[dict]:
    """Small dependency-free lexical retrieval; authorization happens before scoring."""
    import re
    from app.security.prompt_detector import inspect_prompt
    query_terms = set(re.findall(r"[a-z0-9]{3,}", message.lower()))
    ranked = []
    for item in documents:
        # Documents containing obvious instruction attacks are excluded from context.
        inspection = inspect_prompt(item.content)
        if inspection["blocked"]:
            continue
        terms = set(re.findall(r"[a-z0-9]{3,}", f"{item.title} {item.content}".lower()))
        score = len(query_terms & terms) / max(1, len(query_terms))
        if score >= 0.08:
            ranked.append((score, item))
    ranked.sort(key=lambda pair: (-pair[0], pair[1].id))
    return [
        {"id": item.id, "title": item.title, "content": item.content}
        for _, item in ranked[:3]
    ]


def _validate_document_content(content: str) -> None:
    import unicodedata
    from app.security.prompt_detector import inspect_prompt
    if any(unicodedata.category(char) == "Cf" for char in content):
        raise HTTPException(status_code=422, detail="Document contains hidden formatting characters.")
    finding = inspect_prompt(content)
    if finding["blocked"]:
        raise HTTPException(
            status_code=422,
            detail=f"Document rejected by ingestion security check ({finding['rule_id']}).",
        )


_request_times: dict[str, deque] = defaultdict(deque)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    now = monotonic()
    bucket = _request_times[request.client.host if request.client else "unknown"]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= 120:
        return Response("Too many requests", status_code=429)
    bucket.append(now)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'"
    return response


@app.get("/")
def home():
    return {
        "project": "NeuraLock",
        "message": "AI Security Gateway is running",
        "ui": "/ui/",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/database")
def database_health(db: Session = Depends(get_db)):
    db.execute(__import__("sqlalchemy").text("SELECT 1"))
    return {"database": "connected"}


@app.get("/api/auth/status")
def auth_status(db: Session = Depends(get_db)):
    return {"needs_bootstrap": db.query(User).count() == 0}


@app.post("/api/auth/bootstrap")
def bootstrap(request: BootstrapRequest, db: Session = Depends(get_db)):
    if db.query(User).count():
        raise HTTPException(status_code=409, detail="Initial administrator already exists.")
    user = User(
        username=request.username.strip(),
        password_hash=hash_password(request.password),
        organisation_id=request.organisation_id.strip(),
        role="admin",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = issue_session(db, user)
    return {"token": token, "identity": identity_for(user)}


@app.post("/api/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=request.username.strip()).first()
    if user is None or not user.is_active or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = issue_session(db, user)
    return {"token": token, "identity": identity_for(user)}


@app.post("/api/users")
def create_user(request: UserCreateRequest, db: Session = Depends(get_db), admin: User = Depends(current_user)):
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    username = request.username.strip()
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=409, detail="Username already exists.")
    user = User(
        username=username,
        password_hash=hash_password(request.password),
        organisation_id=admin.organisation_id,
        role=request.role,
    )
    db.add(user)
    db.commit()
    return {"status": "created", "username": user.username, "role": user.role}


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(default=None), user: User = Depends(current_user), db: Session = Depends(get_db)):
    # Session revocation is handled by deleting the presented token hash.
    token = authorization.removeprefix("Bearer ").strip() if authorization else ""
    import hashlib
    row = db.query(AuthSession).filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user.id).first()
    if row:
        db.delete(row)
        db.commit()
    return {"status": "signed out"}


@app.get("/api/identity")
def identity(user: User = Depends(current_user)):
    return identity_for(user)


def _conversation_or_404(db: Session, conversation_id: int, identity: dict) -> Conversation:
    conversation = db.get(Conversation, conversation_id)
    if (conversation is None or conversation.user_id != identity["user_id"]
            or conversation.organisation_id != identity["organisation_id"]):
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return conversation


@app.post("/api/chat")
def chat(request: ChatRequest, db: Session = Depends(get_db), user: User = Depends(current_user)):
    identity = identity_for(user)
    if request.conversation_id is None:
        conversation = Conversation(user_id=user.id, organisation_id=user.organisation_id)
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
    else:
        conversation = _conversation_or_404(db, request.conversation_id, identity)

    history = [
        {"role": turn.role, "content": turn.content}
        for turn in (
            db.query(ChatTurn)
            .filter(ChatTurn.conversation_id == conversation.id)
            .order_by(ChatTurn.id.asc())
            .all()
        )
    ]
    documents = _select_relevant_documents(request.message, _allowed_documents(db, identity))
    decision = decide_next_action(request.message, history, documents)

    db.add(
        ChatTurn(
            conversation_id=conversation.id,
            role="user",
            content=decision["user_message"],
        )
    )
    db.add(
        ChatTurn(
            conversation_id=conversation.id,
            role="assistant",
            content=decision["reply"],
            action=decision["action"],
        )
    )
    event = SecurityEvent(
        event_type="chat_decision",
        risk_level=decision["risk"],
        action_taken=decision["action"],
        reason=decision["reason"],
        user_id=user.id,
        organisation_id=user.organisation_id,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "conversation_id": conversation.id,
        "chat": "open",
        "action": decision["action"],
        "reply": decision["reply"],
        "risk": decision["risk"],
        "decided_by": decision["decided_by"],
        "model_connected": decision["model_connected"],
        "documents_in_context": decision["documents_in_context"],
        "event_id": event.id,
    }


@app.get("/api/chat/{conversation_id}")
def chat_history(conversation_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    conversation = _conversation_or_404(db, conversation_id, identity_for(user))
    turns = (
        db.query(ChatTurn)
        .filter(ChatTurn.conversation_id == conversation.id)
        .order_by(ChatTurn.id.asc())
        .all()
    )
    return {
        "conversation_id": conversation.id,
        "chat": "open",
        "turns": [
            {
                "role": turn.role,
                "content": turn.content,
                "action": turn.action,
                "created_at": turn.created_at,
            }
            for turn in turns
        ],
    }


@app.get("/api/security/events")
def security_events(
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
    risk_level: str | None = None,
    action: str | None = None,
):
    limit = max(1, min(limit, 100))

    events_query = db.query(SecurityEvent).filter(
        SecurityEvent.organisation_id == user.organisation_id
        if user.role == "admin"
        else SecurityEvent.user_id == user.id
    )
    if risk_level:
        events_query = events_query.filter(SecurityEvent.risk_level == risk_level)
    if action:
        events_query = events_query.filter(SecurityEvent.action_taken == action)
    events = events_query.order_by(SecurityEvent.id.desc()).limit(limit).all()

    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "risk_level": event.risk_level,
            "action_taken": event.action_taken,
            "reason": event.reason,
            "created_at": event.created_at,
        }
        for event in events
    ]


@app.get("/api/security/summary")
def security_summary(db: Session = Depends(get_db), user: User = Depends(current_user)):
    events = db.query(SecurityEvent).filter(
        SecurityEvent.organisation_id == user.organisation_id
        if user.role == "admin"
        else SecurityEvent.user_id == user.id
    ).all()
    return {
        "total": len(events),
        "high_risk": sum(event.risk_level == "high" for event in events),
        "redactions": sum(event.action_taken == "redact_then_answer" for event in events),
        "refusals": sum(event.action_taken == "refuse_message" for event in events),
    }


@app.get("/api/documents")
def list_documents(db: Session = Depends(get_db), user: User = Depends(current_user)):
    identity = identity_for(user)
    documents = _allowed_documents(db, identity)
    return {
        "organisation_id": identity["organisation_id"],
        "role": identity["role"],
        "documents": [
            {
                "id": document.id,
                "title": document.title,
                "allowed_roles": document.allowed_roles,
                "is_active": document.is_active,
            }
            for document in documents
        ],
    }


@app.post("/api/documents")
def create_document(
    request: DocumentCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    identity = identity_for(user)
    _require_admin(identity)
    _validate_document_content(request.content)

    document = KnowledgeDocument(
        organisation_id=identity["organisation_id"],
        title=request.title,
        content=request.content,
        allowed_roles=_with_admin(list(request.allowed_roles)),
        is_active=True,
        created_by=user.id,
    )
    db.add(document)
    db.commit()
    db.refresh(document)

    event = SecurityEvent(
        event_type="document_created",
        risk_level="low",
        action_taken="created",
        reason=(
            f"Document ID={document.id}; "
            f"Organisation={document.organisation_id}"
        ),
        user_id=user.id,
        organisation_id=user.organisation_id,
    )
    db.add(event)
    db.commit()

    return {
        "status": "created",
        "document_id": document.id,
        "title": document.title,
        "organisation_id": document.organisation_id,
        "allowed_roles": document.allowed_roles,
    }


@app.patch("/api/documents/{document_id}")
def update_document(
    document_id: int,
    request: DocumentUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    identity = identity_for(user)
    _require_admin(identity)
    document = _document_in_org(db, document_id, identity["organisation_id"])
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found.")

    if request.title is not None:
        document.title = request.title
    if request.content is not None:
        _validate_document_content(request.content)
        document.content = request.content
    if request.allowed_roles is not None:
        document.allowed_roles = _with_admin(list(request.allowed_roles))
    if request.is_active is not None:
        document.is_active = request.is_active

    action = "deactivated" if document.is_active is False else "updated"
    event = SecurityEvent(
        event_type="document_updated",
        risk_level="low",
        action_taken=action,
        reason=(
            f"Document ID={document.id}; "
            f"Organisation={document.organisation_id}; "
            f"Active={document.is_active}"
        ),
        user_id=user.id,
        organisation_id=user.organisation_id,
    )
    db.add(event)
    db.commit()
    db.refresh(document)

    return {
        "status": action,
        "document_id": document.id,
        "title": document.title,
        "allowed_roles": document.allowed_roles,
        "is_active": document.is_active,
    }


@app.post("/api/documents/{document_id}/read")
def read_document(
    document_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    identity = identity_for(user)
    document = _document_in_org(db, document_id, identity["organisation_id"])
    allowed = (
        document is not None
        and document.is_active
        and identity["role"] in (document.allowed_roles or [])
    )

    event = SecurityEvent(
        event_type="document_access",
        risk_level="low" if allowed else "medium",
        action_taken="allowed" if allowed else "denied",
        reason=(
            f"Document ID={document_id}; "
            f"Organisation={identity['organisation_id']}; "
            f"Role={identity['role']}; "
            f"{'Access granted' if allowed else 'Access denied'}"
        ),
        user_id=user.id,
        organisation_id=user.organisation_id,
    )
    db.add(event)
    db.commit()

    if document is None or not document.is_active:
        raise HTTPException(
            status_code=404,
            detail="Document unavailable or access denied.",
        )
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail="Document unavailable or access denied.",
        )

    return {
        "status": "allowed",
        "document_id": document.id,
        "title": document.title,
        "content": document.content,
    }


frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
if frontend_dir.is_dir():
    app.mount(
        "/ui",
        StaticFiles(directory=frontend_dir, html=True),
        name="ui",
    )
