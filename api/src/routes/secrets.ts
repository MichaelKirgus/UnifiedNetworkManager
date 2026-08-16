import { Router } from 'express';
import { db } from '../db';
import { eq } from 'drizzle-orm';
import { encrypt } from '../utils/crypto';
import { requireAuth, requirePermission } from '../auth/middleware';
import * as schema from '../db/schema';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// GET /secrets - List all secrets (metadata only)
router.get('/', requireAuth, requirePermission('secrets:read'), async (req, res) => {
  try {
    const secrets = await db.query.secrets.findMany({
      orderBy: (secrets, { desc }) => [desc(secrets.createdAt)],
    });
    
    // Resolve userId to username
    const userIds = [...new Set(secrets.map(s => s.userId))];
    const userMap = new Map<string, string>();

    if (userIds.length > 0) {
      const users = await db.query.users.findMany({
        where: (users, { inArray }) => inArray(users.id, userIds),
      });
      users.forEach(u => userMap.set(u.id, u.username));
    }

    // We only return the ID, label, createdAt, expiresAt, and username, NEVER the encryptedValue
    const sanitizedSecrets = secrets.map(s => ({
      id: s.id,
      label: s.label,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      username: userMap.get(s.userId) ?? 'Unknown',
    }));

    res.status(200).json(sanitizedSecrets);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// POST /secrets - Create a new secret
router.post('/', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { apiKey, apiSecret, label, expiresAt } = req.body ?? {};

  if (!apiKey || !apiSecret) {
    res.status(400).json({ error: 'apiKey and apiSecret are required' });
    return;
  }

  try {
    const secretValue = JSON.stringify({ apiKey, apiSecret, label });
    const encryptedValue = encrypt(secretValue);
    
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    const userId = req.user?.sub;

    if (!userId || typeof userId !== 'string') {
      res.status(401).json({ error: 'User ID not found in token' });
      return;
    }

    await db.insert(schema.secrets).values({
      label,
      id,
      encryptedValue,
      userId,
      expiresAt: expiresAt || null,
      createdAt,
    });

    res.status(201).json({ id, createdAt });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// DELETE /secrets/:id - Remove a secret
router.delete('/:id', requireAuth, requirePermission('secrets:delete'), async (req, res) => {
  const { id } = req.params;

  try {
    await db.delete(schema.secrets).where(eq(schema.secrets.id, id));
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;
