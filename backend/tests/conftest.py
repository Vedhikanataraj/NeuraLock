import os
import tempfile
import pytest

_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db.close()
os.environ["NEURALOCK_DATABASE_URL"] = "sqlite:///" + _db.name.replace("\\", "/")
os.environ["NEURALOCK_ORGANISATION_ID"] = "local"
os.environ["NEURALOCK_ROLE"] = "admin"

from fastapi.testclient import TestClient
from app.db import Base, engine
from app.main import app


@pytest.fixture
def api():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    result = client.post("/api/auth/bootstrap", json={
        "username": "root-user",
        "password": "test-admin-password-123",
        "organisation_id": "NL0001",
    })
    assert result.status_code == 200
    tokens = {"admin": result.json()["token"]}
    admin_headers = {"Authorization": f"Bearer {tokens['admin']}"}
    for role in ("employee", "manager"):
        client.post("/api/users", headers=admin_headers, json={
            "username": f"test-{role}",
            "password": f"test-{role}-password-123",
            "role": role,
        })
        logged_in = client.post("/api/auth/login", json={
            "username": f"test-{role}",
            "password": f"test-{role}-password-123",
        })
        assert logged_in.status_code == 200
        tokens[role] = logged_in.json()["token"]
    headers = {role: {"Authorization": f"Bearer {token}"} for role, token in tokens.items()}
    yield client, headers
    client.close()
