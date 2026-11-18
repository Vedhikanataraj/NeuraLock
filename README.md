# NeuraLock

Local AI security gateway. A chat message is checked for prompt injection and private details, then answered by a local model with only the documents the current role is allowed to see.

## Run

From the `backend` folder, with the repo virtualenv:

```powershell
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000/ui/](http://127.0.0.1:8000/ui/).

The model is optional. Set `NEURALOCK_LLM_BASE_URL` (default `http://127.0.0.1:11434`) and `NEURALOCK_LLM_MODEL` (default `llama3.2`). If the model is not running, chat stays open and a policy reply is returned.

## Identity

The server decides who is calling. Requests cannot send a role.

| Variable | Default | Meaning |
|---|---|---|
| `NEURALOCK_ORGANISATION_ID` | `local` | Document library for this gateway |
| `NEURALOCK_ROLE` | `admin` | `employee`, `manager`, or `admin` |
| `NEURALOCK_DATABASE_URL` | `sqlite:///./neuralock.db` | Database file |

Only `admin` can create, update, and deactivate documents. Read and chat use the active documents whose `allowed_roles` include the current role. Saving a document always keeps `admin` on that list.

## Checks

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest
```
