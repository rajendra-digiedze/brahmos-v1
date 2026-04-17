# brahmos-v1 — SOC Dashboard

FastAPI + SQLite ingest, React UI, Qdrant + Gemini for High/Critical summaries and chat, optional n8n webhooks on **Critical** logs.


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


## Flow Diagram (Data Flow)

```mermaid
flowchart TD
  S[Log Source\nlog_generator or firewall tail] --> I[Ingest API\nPOST /api/logs/ingest]
  I --> DB[(SQLite log store)]
  I --> P[Async processor\nBackgroundTasks]
  P --> V{Severity High/Critical?}
  V -->|Yes| Q[(Qdrant vectors)]
  V -->|No| SKIP[No vector write]
  P --> C{Severity Critical?}
  C -->|Yes| W[Notification sender]
  W --> N8N[n8n webhook]
  C -->|No| END[No escalation]
  UI[Dashboard UI] --> AUTH[Auth APIs]
  UI --> R[Logs/Stats/Chart APIs]
  UI --> CH[Chat API /api/chat]
  R --> DB
  CH --> Q
```

Uses real firewall log traffic. Set `SECURITY_ALERT_WEBHOOK_URL` for Critical webhooks. `GEMINI_API_KEY` enables embeddings and chat.

## Orchestration Diagram (Runtime Sequence)

```mermaid
sequenceDiagram
  participant LS as Log Source
  participant API as Ingest API
  participant DB as SQLite
  participant AP as Async Processor
  participant QD as Qdrant
  participant NS as Notification Sender
  participant N8N as n8n Webhook
  participant UI as Dashboard
  participant AUTH as Auth API
  participant CHAT as Chat API

  LS->>API: POST /api/logs/ingest
  API->>DB: Save raw log
  API-->>AP: Trigger background processing

  AP->>AP: Parse + severity branch
  alt High/Critical
    AP->>QD: Embed + upsert vector
  else Low/Medium
    AP->>AP: Skip vector write
  end

  alt Critical
    AP->>NS: Trigger escalation
    NS->>N8N: POST webhook payload
  else Not Critical
    AP->>AP: No escalation
  end

  UI->>AUTH: Login/Register
  AUTH-->>UI: Bearer token
  UI->>API: GET /api/logs, /api/logs/stats, /api/logs/chart
  API->>DB: Query filtered data
  API-->>UI: Return dashboard payloads

  UI->>CHAT: POST /api/chat
  CHAT->>QD: Retrieve relevant vectors
  CHAT-->>UI: Response/report
```

## Architecture Diagram (System Components)

```mermaid
flowchart LR
  subgraph Sources
    LS[Windows Firewall Tail / Log Generator]
  end

  subgraph Frontend
    UI[React SOC Dashboard]
  end

  subgraph Backend["FastAPI Backend"]
    AUTH[Auth APIs]
    ING[Ingest API]
    QRY[Logs/Stats/Chart APIs]
    CHAT[Chat API]
    PROC[Background Processor]
    NOTIF[Alerting]
  end

  subgraph Storage
    DB[(SQLite logs/users)]
    QD[(Qdrant vectors)]
  end

  subgraph Integrations
    GEM[Gemini API]
    N8N[n8n Webhook]
  end

  LS --> ING
  UI --> AUTH
  UI --> QRY
  UI --> CHAT
  ING --> DB
  ING --> PROC
  PROC --> QD
  PROC --> NOTIF
  QRY --> DB
  CHAT --> QD
  QD --> GEM
  NOTIF --> N8N
```
