import { Router, Response } from 'express';
import { prisma }         from '../../config/prisma';
import { piiScanQueue }   from '../../config/queue';
import { AuthRequest }    from '../../types';

const router = Router();

const computeRiskScore = (count: number | null): 'low' | 'medium' | 'high' => {
  if (!count) return 'low';
  if (count > 20) return 'high';
  if (count > 5)  return 'medium';
  return 'low';
};

// ─── GET /api/admin/stats ─────────────────────────────────

router.get('/', async (_req: AuthRequest, res: Response) => {
  try {
    const [
      totalFiles,
      pendingFiles,
      processingFiles,
      sanitizedFiles,
      failedFiles,
      totalUsers,
      activeUsers,
      storageAgg,
      topRiskFilesRaw,
      recentActivity,
      filesWithPii,
    ] = await Promise.all([
      prisma.file.count(),
      prisma.file.count({ where: { status: 'PENDING' } }),
      prisma.file.count({ where: { status: 'PROCESSING' } }),
      prisma.file.count({ where: { status: 'SANITIZED' } }),
      prisma.file.count({ where: { status: 'ERROR' } }),
      prisma.user.count(),
      prisma.user.count({ where: { isActive: true } }),
      prisma.file.aggregate({ _sum: { sizeBytes: true } }),
      prisma.file.findMany({
        where:   { status: 'SANITIZED' },
        orderBy: { entityCount: 'desc' },
        take:    5,
        select:  { id: true, originalName: true, entityCount: true, entitiesByType: true, sanitizedAt: true, mimeType: true },
      }),
      prisma.auditLog.findMany({
        orderBy: { createdAt: 'desc' },
        take:    20,
        include: {
          user: { select: { name: true, email: true } },
          file: { select: { originalName: true } },
        },
      }),
      prisma.file.findMany({
        where:  { status: 'SANITIZED', entitiesByType: { not: undefined } },
        select: { entitiesByType: true },
      }),
    ]);

    // Aggregate PII detections across all sanitized files
    const piiCounts: Record<string, number> = {};
    for (const f of filesWithPii) {
      if (f.entitiesByType && typeof f.entitiesByType === 'object') {
        for (const [type, count] of Object.entries(f.entitiesByType as Record<string, number>)) {
          piiCounts[type] = (piiCounts[type] ?? 0) + count;
        }
      }
    }

    const piiDetectionsByType = Object.entries(piiCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);

    // Queue stats from BullMQ
    let queueWaiting = 0;
    let queueActive = 0;
    let queueFailed = 0;
    let queueCompleted = 0;
    try {
      [queueWaiting, queueActive, queueFailed, queueCompleted] = await Promise.all([
        piiScanQueue.getWaitingCount(),
        piiScanQueue.getActiveCount(),
        piiScanQueue.getFailedCount(),
        piiScanQueue.getCompletedCount(),
      ]);
    } catch (err) {
      console.error('[Stats] Queue metrics unavailable:', err);
    }

    // Original files + sanitized copies both live in R2
    const originalBytes = Number(storageAgg._sum.sizeBytes ?? 0);
    // Rough estimate: sanitized files ≈ same size as originals
    const sanitizedCount = sanitizedFiles;
    const totalStorageBytes = originalBytes * (sanitizedCount > 0 ? 2 : 1);

    res.json({
      totalFiles,
      pendingFiles,
      processingFiles,
      sanitizedFiles,
      failedFiles,
      totalUsers,
      activeUsers,
      storage: {
        usedBytes: totalStorageBytes,
        totalFiles,
        limitBytes: 10 * 1024 * 1024 * 1024, // R2 free tier: 10 GB
      },
      topRiskFiles: topRiskFilesRaw.map((f) => ({
        ...f,
        riskScore: computeRiskScore(f.entityCount),
      })),
      recentActivity,
      piiDetectionsByType,
      queue: {
        waiting:   queueWaiting,
        active:    queueActive,
        failed:    queueFailed,
        completed: queueCompleted,
      },
    });
  } catch (err) {
    console.error('[Stats]', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ─── GET /api/admin/stats/queue ───────────────────────────

router.get('/queue', async (_req: AuthRequest, res: Response) => {
  try {
    const [waiting, active, failed, completed, delayed] = await Promise.all([
      piiScanQueue.getWaitingCount(),
      piiScanQueue.getActiveCount(),
      piiScanQueue.getFailedCount(),
      piiScanQueue.getCompletedCount(),
      piiScanQueue.getDelayedCount(),
    ]);
    res.json({ waiting, active, failed, completed, delayed });
  } catch {
    res.status(500).json({ error: 'Failed to fetch queue stats' });
  }
});

// ─── GET /api/admin/stats/overview ───────────────────────
// Light summary for dashboard header KPIs

router.get('/overview', async (_req: AuthRequest, res: Response) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [total, sanitized, failed, newThisMonth] = await Promise.all([
      prisma.file.count(),
      prisma.file.count({ where: { status: 'SANITIZED' } }),
      prisma.file.count({ where: { status: 'ERROR' } }),
      prisma.file.count({ where: { uploadedAt: { gte: thirtyDaysAgo } } }),
    ]);

    res.json({ total, sanitized, failed, newThisMonth });
  } catch {
    res.status(500).json({ error: 'Failed to fetch overview' });
  }
});

export default router;
