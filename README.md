# brahmos-v1 — dZshield SOC Dashboard

FastAPI + SQLite ingest, React UI, Qdrant + Gemini for High/Critical summaries and chat, optional n8n webhooks on **Critical** logs.

## Data Flow Diagram

```mermaid
flowchart TD
  S[Log Source\nlog_generator or firewall tail] --> I[Ingest API\nPOST /api/logs/ingest]
  I --> DB[(SQLite log store)]
  I --> P[Async processor]
  P --> V{Severity High/Critical?}
  V -->|Yes| Q[(Qdrant vectors)]
  V -->|No| SKIP[No vector write]
  P --> C{Severity Critical?}
  C -->|Yes| W[Notification sender]
  W --> N8N[n8n webhook]
  C -->|No| END[No escalation]
  DB --> R[Logs/Stats/Chart APIs]
  Q --> CH[Chat API /api/chat]
  R --> UI[Dashboard UI]
  CH --> UI
```

Docker/Linux uses synthetic logs. Set `SECURITY_ALERT_WEBHOOK_URL` for Critical webhooks. `GEMINI_API_KEY` enables embeddings and chat.

## Orchestration Pattern

- **Primary:** Reactive event-driven pipeline
- **Execution style:** Conditional Parallel Fan-Out with Sequential branch steps
- **Hierarchical control-tree:** Not used
- **One-line classification:** Reactive event-driven pipeline with conditional parallel fan-out and sequential branch execution.

## Setup

```bash
git clone <repo-url> brahmos-v1 && cd brahmos-v1
```

Create **`backend/.env`**:

```env
GEMINI_API_KEY=
SECURITY_ALERT_WEBHOOK_URL=
```

Deploy:

```bash
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:5173 |
| API | http://localhost:8000/docs |
| n8n | http://localhost:5678 |

**n8n (optional):** Webhook (POST) → e.g. Gmail → paste Production URL into `SECURITY_ALERT_WEBHOOK_URL` → `docker compose up -d backend`. Payload shape: `backend/notifications.py`.

**Local dev:** `backend/` → `uvicorn main:app --reload` · `frontend/` → `npm install && npm run dev` (optional `VITE_API_BASE_URL`). Qdrant on `QDRANT_URL` if needed.

## Credits

**dZshield / brahmos-v1** — *rajendrapanga970-crypto*
