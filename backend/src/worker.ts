/**
 * BullMQ Worker — PII Scan Pipeline
 *
 * Stages:
 *  1. Set file status → PROCESSING
 *  2. Download original from Cloudflare R2
 *  3. POST /analyze  → Python PII Engine  (entity detection)
 *  4. POST /sanitize → Python PII Engine  (entity redaction)
 *  5. Upload sanitized file → Cloudflare R2
 *  6. Update DB   status → SANITIZED
 *  7. Write SCAN_COMPLETE audit log
 *  8. Notify uploader via email
 *
 * The ML endpoint (PII_ENGINE_URL) is set in .env and injected when ready.
 */

import 'dotenv/config';
import { Worker, Job } from 'bullmq';
import axios           from 'axios';
import FormData        from 'form-data';
import { redisConnection } from './config/redis';
import { prisma }       from './config/prisma';
import { r2Service }    from './services/r2.service';
import { auditService } from './services/audit.service';
import { emailService } from './services/email.service';
import { PiiScanJobData } from './config/queue';

const PII_ENGINE_URL  = process.env.PII_ENGINE_URL!;
const CONCURRENCY     = parseInt(process.env.WORKER_CONCURRENCY ?? '5', 10);

// ─── Timeout per MIME type (ms) — generous for free-tier cold starts ──
// For large files (>2 MB) add 60 s per MB to handle chunked analysis.

function jobTimeout(mimeType: string, fileSizeBytes = 0): number {
  const sizeMB = fileSizeBytes / (1024 * 1024);
  const sizeBonus = sizeMB > 2 ? Math.ceil(sizeMB) * 60_000 : 0;
  if (mimeType === 'application/pdf') return 300_000 + sizeBonus;
  if (mimeType.includes('word'))      return 180_000 + sizeBonus;
  if (mimeType.startsWith('image/'))  return 300_000 + sizeBonus;
  return 120_000 + sizeBonus;
}

// ─── Wake the PII engine (Render free tier sleeps after 15 min) ───────

async function wakePiiEngine(): Promise<void> {
  try {
    await axios.get(`${PII_ENGINE_URL}/health`, { timeout: 120_000 });
    console.log('[Worker] PII engine is awake');
  } catch {
    console.warn('[Worker] PII engine wake-up call failed, proceeding anyway');
  }
}

// ─── Main processor ──────────────────────────────────────

async function processJob(job: Job<PiiScanJobData>): Promise<void> {
  const { fileId, originalKey, mimeType, ext } = job.data;
  console.log(`[Worker] Job ${job.id} started — fileId=${fileId}`);

  // Stage 1 — mark as processing
  await prisma.file.update({
    where: { id: fileId },
    data:  { status: 'PROCESSING' },
  });

  const startTime = Date.now();

  // Stage 2 — download original from R2 into a buffer
  const r2Res = await r2Service.download(originalKey);
  const chunks: Buffer[] = [];
  for await (const chunk of r2Res.Body as AsyncIterable<Uint8Array>) {
    chunks.push(Buffer.from(chunk));
  }
  const fileBuffer = Buffer.concat(chunks);

  const timeout = jobTimeout(mimeType, fileBuffer.length);
  console.log(`[Worker] File size: ${(fileBuffer.length / 1024 / 1024).toFixed(2)} MB, timeout: ${timeout / 1000}s`);

  // Stage 2.5 — wake PII engine (cold start on Render free tier)
  await wakePiiEngine();

  // Stage 3 — call /analyze on Python PII Engine
  const analyzeForm = new FormData();
  analyzeForm.append('file', fileBuffer, { filename: `file.${ext}`, contentType: mimeType });

  const analyzeRes = await axios.post<{
    entities: Array<{ type: string; text: string; start: number; end: number; score: number }>;
    stats:    { total: number; by_type: Record<string, number> };
  }>(
    `${PII_ENGINE_URL}/analyze`,
    analyzeForm,
    { headers: analyzeForm.getHeaders(), timeout },
  );

  const { entities, stats } = analyzeRes.data;

  // Stage 4 — call /sanitize on Python PII Engine
  const sanitizeForm = new FormData();
  sanitizeForm.append('file',     fileBuffer,              { filename: `file.${ext}`, contentType: mimeType });
  sanitizeForm.append('entities', JSON.stringify(entities));

  const sanitizeRes = await axios.post<Buffer>(
    `${PII_ENGINE_URL}/sanitize`,
    sanitizeForm,
    { headers: sanitizeForm.getHeaders(), responseType: 'arraybuffer', timeout },
  );

  const sanitizedBuffer = Buffer.from(sanitizeRes.data);
  const sanitizedKey    = r2Service.buildKey('sanitized', fileId, ext);

  // Stage 5 — upload sanitized file to R2
  await r2Service.upload(sanitizedKey, sanitizedBuffer, mimeType);

  const processingTimeMs = Date.now() - startTime;

  // Stage 6 — update DB row
  await prisma.file.update({
    where: { id: fileId },
    data: {
      status:          'SANITIZED',
      sanitizedKey,
      entityCount:     stats.total,
      entitiesByType:  stats.by_type,
      processingTimeMs,
      sanitizedAt:     new Date(),
      lastError:       null,
    },
  });

  // Stage 7 — audit log
  await auditService.log({
    action: 'SCAN_COMPLETE',
    fileId,
    metadata: {
      entityCount:     stats.total,
      entitiesByType:  stats.by_type,
      processingTimeMs,
    },
  });

  // Stage 8 — email notification
  const file = await prisma.file.findUnique({
    where:   { id: fileId },
    include: { uploader: { select: { email: true, name: true } } },
  });
  if (file?.uploader) {
    try {
      await emailService.sendFileReady(
        file.uploader.email,
        file.uploader.name,
        file.originalName,
      );
    } catch (err) {
      console.error('[Worker] File-ready email failed; sanitization remains complete:', err);
    }
  }

  console.log(`[Worker] Job ${job.id} completed in ${processingTimeMs}ms — ${stats.total} PII entities`);
}

// ─── Worker instance ─────────────────────────────────────

const worker = new Worker<PiiScanJobData>('pii-scan', processJob, {
  connection:  redisConnection,
  concurrency: CONCURRENCY,
});

// ─── Failure handler ─────────────────────────────────────

worker.on('failed', async (job, err) => {
  if (!job) return;
  const requestError = err as Error & {
    response?: { status?: number; data?: unknown };
    config?: { url?: string };
  };
  console.error(`[Worker] Job ${job.id} failed (attempt ${job.attemptsMade}):`, {
    message: requestError.message,
    status: requestError.response?.status,
    url: requestError.config?.url,
    response: requestError.response?.data,
  });

  const maxAttempts = job.opts.attempts ?? 3;

  if (job.attemptsMade >= maxAttempts) {
    // All retries exhausted — mark as error
    await prisma.file.update({
      where: { id: job.data.fileId },
      data:  { status: 'ERROR', lastError: err.message },
    });

    await auditService.log({
      action: 'SCAN_FAILED',
      fileId: job.data.fileId,
      metadata: { error: err.message, attempts: job.attemptsMade },
    });
  }
});

worker.on('completed', (job) => {
  console.log(`[Worker] Job ${job.id} ✓`);
});

worker.on('error', (err) => {
  console.error('[Worker] Worker error:', err.message);
});

console.log(`[Worker] Started — concurrency=${CONCURRENCY}  PII_ENGINE=${PII_ENGINE_URL}`);
