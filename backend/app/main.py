from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.chatbot import decide_next_action
from app.db import Base, engine, get_db
from app.models import ChatTurn, Conversation, KnowledgeDocument, SecurityEvent
from app.settings import current_identity

Base.metadata.create_all(bind=engine)

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


@app.get("/api/identity")
def identity():
    current = current_identity()
    return {
        "organisation_id": current["organisation_id"],
        "role": current["role"],
    }


def _conversation_or_404(db: Session, conversation_id: int) -> Conversation:
    conversation = db.get(Conversation, conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return conversation


@app.post("/api/chat")
def chat(request: ChatRequest, db: Session = Depends(get_db)):
    identity = current_identity()
    if request.conversation_id is None:
        conversation = Conversation()
        db.add(conversation)
        db.commit()
        db.refresh(conversation)
    else:
        conversation = _conversation_or_404(db, request.conversation_id)

    history = [
        {"role": turn.role, "content": turn.content}
        for turn in (
            db.query(ChatTurn)
            .filter(ChatTurn.conversation_id == conversation.id)
            .order_by(ChatTurn.id.asc())
            .all()
        )
    ]
    documents = [
        {"title": document.title, "content": document.content}
        for document in _allowed_documents(db, identity)
    ]
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
def chat_history(conversation_id: int, db: Session = Depends(get_db)):
    conversation = _conversation_or_404(db, conversation_id)
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
):
    limit = max(1, min(limit, 100))

    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.id.desc())
        .limit(limit)
        .all()
    )

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


@app.get("/api/documents")
def list_documents(db: Session = Depends(get_db)):
    identity = current_identity()
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
):
    identity = current_identity()
    _require_admin(identity)

    document = KnowledgeDocument(
        organisation_id=identity["organisation_id"],
        title=request.title,
        content=request.content,
        allowed_roles=_with_admin(list(request.allowed_roles)),
        is_active=True,
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
):
    identity = current_identity()
    _require_admin(identity)
    document = _document_in_org(db, document_id, identity["organisation_id"])
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found.")

    if request.title is not None:
        document.title = request.title
    if request.content is not None:
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
):
    identity = current_identity()
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
