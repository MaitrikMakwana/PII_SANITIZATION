# Change Log

## 2026-08-22

### Authentication and Dashboard

- Created the Prisma database schema with `npm run db:push`.
- Seeded the initial accounts:
  - Admin: `admin@pill.com` / `Admin@123`
  - User: `user@pill.com` / `User@123`
- Configured frontend CORS for the active Vite port `5174`.
- Verified `POST /api/auth/login` returns `200 OK` with a JWT.
- Fixed admin dashboard loading when Redis queue metrics are unavailable. The dashboard now returns database statistics with queue counts set to zero when Redis is unavailable.

### Queue and File Processing

- Corrected the Upstash Redis URL to use the `rediss://` scheme and port `6379`.
- Started the BullMQ worker with `npm run dev:worker`.
- Confirmed the Python PII engine is healthy on `http://localhost:8000/health`.
- Confirmed uploaded files can move from `PENDING` to `SANITIZED`.
- Made Brevo file-ready email notifications non-blocking. An invalid Brevo key no longer marks a successfully sanitized file as failed.

### PII Detection and Sanitization

- Changed the sanitizer so detected names, email addresses, and locations are masked instead of remaining visible.
- Preserved the existing type-specific masking behavior for phones, Aadhaar numbers, PAN, cards, SSNs, IP addresses, UPI IDs, IFSC codes, and other detected entities.
- Verified an analyze-then-sanitize request detects four entities and returns masked output.
- Verified a file downloaded from the API contains masked PII values.

### Validation

- Backend TypeScript build passes with `npm run build` from `backend/`.
- Frontend production build passes with `npm run build` from the project root.
- Dashboard stats endpoint returns `200 OK`.
- End-to-end upload and sanitization test completed successfully.

### Remaining Configuration

- `BREVO_API_KEY` currently returns `401 Key not found` from Brevo. File sanitization still completes, but file-ready email notifications remain unavailable until a valid Brevo API key is configured in `backend/.env`.

## Local Development Commands

Run each service in its own terminal:

```bash
# Frontend
npm run dev

# Backend API
cd backend
npm run dev

# BullMQ worker
cd backend
npm run dev:worker

# Python PII engine
cd pii-engine
source venv/bin/activate
python3 main.py
```

The local frontend runs at `http://localhost:5174/` when port `5173` is already occupied. The backend API runs at `http://localhost:3001` and the PII engine runs at `http://localhost:8000`.
