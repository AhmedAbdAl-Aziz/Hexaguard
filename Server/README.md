# HexaGuard — Flask Backend

## Tech Stack
- **Python 3.10+** / Flask 3.1
- **MongoDB** (via flask-pymongo)
- **JWT** authentication (flask-jwt-extended)
- **WebSockets** real-time push (flask-socketio + eventlet)
- **CORS** enabled for the React frontend (flask-cors)

---

## Project Structure

```
Server/
├── app.py                  ← Flask app factory + startup entry point
├── config.py               ← Environment-based configuration
├── extensions.py           ← Shared extensions (mongo, jwt, socketio)
├── models/
│   ├── user.py             ← User schema, password hashing, serialization
│   ├── cve.py              ← CVE schema and serialization
│   └── alert.py            ← Alert schema and serialization
├── routes/
│   ├── auth.py             ← POST /api/auth/login, GET /api/auth/me
│   ├── cves.py             ← GET/POST /api/cves
│   ├── customers.py        ← GET/POST /api/customers, PUT stack & notifications
│   └── alerts.py           ← GET /api/alerts, PUT read, GET stats
├── services/
│   ├── alert_dispatcher.py ← Core rules engine (tech stack matching + alert creation)
│   └── notifications.py    ← Email (SMTP), Slack webhook, custom webhook senders
├── scripts/
│   ├── cve_nvd_crawler.py  ← NVD API crawler (run as cron or --watch daemon)
│   └── seed_db.py          ← Seeds initial CVE + customer data into MongoDB
├── requirements.txt
├── .env.example
└── README.md
```

---

## Setup & Run

### 1. Prerequisites
- Python 3.10 or higher
- MongoDB running on `localhost:27017`  
  (Install: https://www.mongodb.com/try/download/community)

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure environment
```bash
cp .env.example .env
# Edit .env with your settings
```

Key values in `.env`:
| Variable | Description |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `JWT_SECRET_KEY` | Secret key for signing JWTs — **change in production** |
| `SCRAPER_API_TOKEN` | Bearer token used by crawler scripts to POST CVEs |
| `FRONTEND_ORIGIN` | React dev server URL for CORS (default: `http://localhost:5173`) |

### 4. Seed the database
Populates MongoDB with the initial CVEs and customer accounts from mockData:
```bash
python scripts/seed_db.py
```

Default credentials after seeding:
| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |
| `acme_security` | `customer123` | Customer |
| `globaltech_ops` | `customer123` | Customer |
| `securebank_infosec` | `customer123` | Customer |

### 5. Start the backend
```bash
python app.py
```
Server runs at **http://localhost:5000**

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/auth/login` | POST | Public | Login → returns JWT |
| `/api/auth/me` | GET | JWT | Current user profile |
| `/api/health` | GET | Public | Health check |
| `/api/cves/` | GET | JWT | List CVEs (search, severity, technology filters) |
| `/api/cves/` | POST | Scraper token or Admin JWT | Ingest CVE + trigger alert dispatcher |
| `/api/customers/` | GET | Admin JWT | List all customers |
| `/api/customers/` | POST | Admin JWT | Provision new customer |
| `/api/customers/<id>/stack` | PUT | JWT (admin or self) | Update tech stack |
| `/api/customers/<id>/notifications` | PUT | JWT (admin or self) | Update notification preferences |
| `/api/alerts/` | GET | JWT | Alert history (customers see own alerts only) |
| `/api/alerts/<id>/read` | PUT | JWT | Mark alert as read |
| `/api/alerts/stats` | GET | Admin JWT | Alert statistics |

---

## CVE Crawler Script

The NVD crawler queries the NIST NVD API for recently published CVEs and ingests them into HexaGuard.

**One-shot run:**
```bash
python scripts/cve_nvd_crawler.py
```

**Watch mode (runs every hour):**
```bash
python scripts/cve_nvd_crawler.py --watch
```

**Optional: Get an NVD API key** for higher rate limits:
https://nvd.nist.gov/developers/request-an-api-key  
Add it to `.env` as `NVD_API_KEY=your_key_here`

---

## WebSocket Events

The backend emits these Socket.IO events to connected frontend clients:

| Event | Payload | Trigger |
|---|---|---|
| `ALERT_DISPATCHED` | `{ alert, cve_id, severity, customer_id, customer_name }` | When a CVE matches a customer's tech stack |
| `CVE_INGESTED` | Serialized CVE object | When a new CVE is ingested |

Clients should emit `JOIN` after login with `{ userId, role }` to receive room-targeted alerts.

Connect from the frontend:
```js
import { io } from 'socket.io-client';
const socket = io('http://localhost:5000');
socket.on('ALERT_DISPATCHED', (payload) => { /* handle */ });
```

---

## Running Both Frontend and Backend

Open two terminals:

**Terminal 1 — Backend:**
```bash
# From Server/
python app.py
```

**Terminal 2 — Frontend:**
```bash
# From Client/
npm run dev
```

Frontend at http://localhost:5173  
Backend API at http://localhost:5000
