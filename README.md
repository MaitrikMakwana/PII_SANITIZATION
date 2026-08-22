# PII Data Sanitization Platform

A full-stack platform for detecting and sanitizing Personally Identifiable Information (PII) across multiple file formats. Built with React, Express.js, and a Python ML engine powered by Presidio + spaCy.

---

## Features

### Authentication & Authorization
- JWT-based login with role-based access control (Admin / Standard User)
- Forgot-password & reset-password flow via email (Brevo)
- Profile management with avatar and password change

### Admin Dashboard
- Real-time KPI cards (total files, sanitized count, processing, errors)
- PII detection charts (by type, distribution pie chart) via Recharts
- R2 cloud storage usage widget with visual bar
- Recent activity feed

### File Management
- Upload files (drag & drop or click) — supports TXT, CSV, JSON, XML, SQL, PDF, DOCX, PNG, JPG
- Async 7-stage processing pipeline (BullMQ worker)
- Real-time upload queue with per-stage progress tracking
- Search files by name
- Filter by status (Pending / Processing / Sanitized / Error)
- Filter by file type (PDF, DOCX, TXT, CSV, JSON, SQL, Images)
- File detail page with side-by-side original vs sanitized view
- Download original (admin) or sanitized file
- Re-scan / delete files with confirmation modal
- Storage auto-refresh on file completion or deletion

### Image Sanitization (PNG / JPG)
- OCR via Tesseract with preprocessing (grayscale, contrast, sharpen, upscale)
- Presidio NLP-based PII detection on OCR text
- Regex fallback patterns for Indian PII (PAN, Aadhaar, VID, phone, email)
- ORGANIZATION / NRP entity filter to avoid blacking out card headers
- Black-rectangle redaction on detected PII bounding boxes

### Format-Preserving Sanitization
- **DOCX** — Run-level replacement preserving bold, italic, color, font
- **PDF** — PyMuPDF redaction annotations

### User Management (Admin)
- Create, activate/deactivate users, change roles
- User list with status badges

### Audit Logs (Admin)
- Complete activity trail with filtering by action, user, date
- CSV export for compliance

### User Portal
- View and download only sanitized files
- Personal dashboard with file stats
- Profile settings

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS v4, shadcn/ui, Recharts, Lucide, Sonner |
| Backend | Express.js, TypeScript, Prisma ORM, BullMQ, Zod, Helmet, CORS |
| Database | Neon PostgreSQL 16 |
| Queue | BullMQ + Upstash Redis |
| Storage | Cloudflare R2 (S3-compatible) |
| Email | Brevo (transactional) |
| PII Engine | Python 3.13, FastAPI, Presidio, spaCy (en_core_web_lg), PyMuPDF, python-docx, Tesseract OCR, Pillow |

---

## Prerequisites

- **Node.js** >= 18
- **npm** >= 9
- **Python** >= 3.10
- **Tesseract OCR** >= 5.x (for image sanitization)
- **Neon PostgreSQL** account (or any PostgreSQL 16 instance)
- **Upstash Redis** account
- **Cloudflare R2** bucket
- **Brevo** API key (for email notifications)

---

## Installation — Step by Step

### 1. Clone the Repository

```bash
git clone https://github.com/MaitrikMakwana/PII-DATA-SANITIZATION.git
cd PII-DATA-SANITIZATION
```

### 2. Frontend Setup

```bash
# Install frontend dependencies (from project root)
npm install
```

### 3. Backend Setup

```bash
cd backend

# Install backend dependencies
npm install

# Generate Prisma client
npx prisma generate
```

Create **`backend/.env`** with the following variables:

```env
# Server
PORT=3001
NODE_ENV=development
CORS_ORIGIN=http://localhost:5173

# Database (Neon PostgreSQL)
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require

# Auth
JWT_SECRET=your-secret-key
JWT_EXPIRES_IN=7d

# Cloudflare R2
R2_ENDPOINT=https://your-account-id.r2.cloudflarestorage.com
R2_ACCESS_KEY_ID=your-access-key
R2_SECRET_ACCESS_KEY=your-secret-key
R2_BUCKET_NAME=your-bucket-name

# Upstash Redis
REDIS_URL=rediss://default:password@host:port

# Brevo Email
BREVO_API_KEY=your-brevo-api-key
BREVO_FROM_EMAIL=noreply@yourdomain.com
BREVO_FROM_NAME=PII Sanitize

# PII Engine
PII_ENGINE_URL=http://localhost:8000

# Worker
WORKER_CONCURRENCY=3
MAX_FILE_SIZE_MB=50
```

Push schema to the database:

```bash
# Create tables in PostgreSQL
npx prisma db push
```

### 4. Python PII Engine Setup

```bash
cd pii-engine

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows

# Install Python dependencies
pip install -r requirements.txt

# Download spaCy English model
python3 -m spacy download en_core_web_lg
```

### 5. Install Tesseract OCR (for image sanitization)

```bash
# macOS
brew install tesseract

# Ubuntu / Debian
sudo apt-get install tesseract-ocr

# Windows — download installer from https://github.com/UB-Mannheim/tesseract/wiki
```

Verify installation:

```bash
tesseract --version
```

---

## Running the Application

You need **4 terminal windows** running simultaneously.

**Terminal 1 — Python PII Engine (port 8000)**

```bash
cd pii-engine
source venv/bin/activate
python3 main.py
```

Wait for: `Uvicorn running on http://0.0.0.0:8000`

**Terminal 2 — Backend API Server (port 3001)**

```bash
cd backend
npm run dev
```

Wait for: `🚀 Server running on http://localhost:3001`

**Terminal 3 — BullMQ Worker**

```bash
cd backend
npm run dev:worker
```

Wait for: `[Worker] Started`

**Terminal 4 — Frontend (port 5173)**

```bash
npm run dev
```

Wait for: `Local: http://localhost:5173/`

Open **http://localhost:5173** in your browser.

---

## Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@pill.com | Admin@123 |
| User | user@pill.com | user@123 |

---

## Supported File Formats

| Format | Extensions | Sanitization Method |
|--------|-----------|-------------------|
| Plain Text | .txt | Text replacement |
| CSV | .csv | Text replacement |
| JSON | .json | Text replacement |
| XML | .xml | Text replacement |
| SQL | .sql | Text replacement |
| PDF | .pdf | PyMuPDF redaction annotations |
| Word | .docx | Run-level replacement (preserves formatting) |
| Images | .png, .jpg, .jpeg | OCR + black-rectangle redaction |

## PII Types Detected

- Email Addresses
- Phone Numbers (Indian & international)
- Aadhaar Numbers (Indian National ID)
- PAN Numbers (Permanent Account Number)
- Credit Card Numbers
- CVV Codes
- Names
- Addresses
- Date of Birth
- IP Addresses
- UPI IDs
- IFSC Codes
- GSTIN, Passport, Voter ID, Vehicle Registration (Indian)

---

## Architecture

### 7-Stage PII Pipeline (BullMQ Worker)

1. **Download** — Fetch original file from Cloudflare R2
2. **Analyze** — POST to Python PII Engine `/analyze`
3. **Sanitize** — POST to Python PII Engine `/sanitize`
4. **Upload** — Store sanitized file back to R2
5. **Update DB** — Save entity count, types, processing time
6. **Audit Log** — Record scan completion
7. **Email** — Notify uploader via Brevo

### API Endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | Public | Login and receive JWT |
| POST | `/api/auth/logout` | Auth | Invalidate session |
| GET | `/api/auth/me` | Auth | Current user info |
| POST | `/api/auth/forgot-password` | Public | Send reset email |
| POST | `/api/auth/reset-password` | Public | Reset with token |
| GET | `/api/admin/files` | Admin | List files (search, status, mimeType filters) |
| POST | `/api/admin/files/upload` | Admin | Upload file |
| DELETE | `/api/admin/files/:id` | Admin | Delete file |
| POST | `/api/admin/files/:id/rescan` | Admin | Re-queue for scanning |
| GET | `/api/admin/users` | Admin | List all users |
| POST | `/api/admin/users` | Admin | Create user |
| PUT | `/api/admin/users/:id` | Admin | Update user |
| GET | `/api/admin/stats` | Admin | Dashboard KPIs |
| GET | `/api/admin/storage` | Admin | R2 storage usage |
| GET | `/api/admin/audit-logs` | Admin | Paginated audit trail |
| GET | `/api/admin/audit-logs/export` | Admin | Export CSV |
| GET | `/api/files` | User | List sanitized files |
| GET | `/api/files/:id/sanitized` | User | Download sanitized |
| GET | `/api/profile` | Auth | View profile |
| PUT | `/api/profile` | Auth | Update profile |
| PUT | `/api/profile/password` | Auth | Change password |

### Project Structure

```
PII-DATA-SANITIZATION/
├── src/                        # Frontend (React + TypeScript)
│   ├── app/
│   │   ├── App.tsx
│   │   └── components/ui/     # shadcn/ui components
│   ├── components/
│   │   ├── AdminDashboard.tsx  # Admin panel (Dashboard/Files/Users/Audit/Settings)
│   │   ├── UserDashboard.tsx   # User portal
│   │   ├── LoginPage.tsx       # Auth page
│   │   ├── Sidebar.tsx         # Navigation
│   │   ├── FileDetailPage.tsx  # File detail & PII analysis
│   │   └── ...
│   ├── lib/
│   │   ├── api.ts             # API client layer
│   │   ├── auth-context.tsx   # Auth context provider
│   │   └── utils.ts
│   ├── types/index.ts
│   └── styles/
├── backend/                    # Express.js API + Worker
│   ├── prisma/
│   │   ├── schema.prisma      # DB models: User, File, AuditLog
│   │   └── seed.ts            # Default accounts
│   └── src/
│       ├── config/            # Prisma, Redis, R2, BullMQ, Multer
│       ├── middleware/        # Auth, RBAC, Error handling
│       ├── services/          # Audit, Email, R2 services
│       ├── routes/            # Auth, Admin, User routes
│       ├── worker.ts          # 7-stage PII pipeline
│       └── index.ts           # Express entry point
├── pii-engine/                 # Python PII Engine (FastAPI)
│   ├── main.py                # FastAPI app + sanitization logic
│   ├── parsers.py             # File parsers (TXT, PDF, DOCX, SQL, CSV, JSON, XML, images)
│   └── requirements.txt
├── package.json               # Frontend dependencies
└── vite.config.ts
```

---

## Security

- JWT authentication with role-based access control
- Helmet security headers + CORS
- Bcrypt password hashing
- Zod request validation
- Audit logging for all sensitive actions
- Users cannot access original files or raw PII values
- Rate limiting on auth endpoints

---

## License

MIT
