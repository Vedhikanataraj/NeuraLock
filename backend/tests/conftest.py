import os
import tempfile

_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db.close()
os.environ["NEURALOCK_DATABASE_URL"] = "sqlite:///" + _db.name.replace("\\", "/")
os.environ["NEURALOCK_ORGANISATION_ID"] = "local"
os.environ["NEURALOCK_ROLE"] = "admin"
