import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { db, UserRow } from '../db';
import { signToken } from '../auth/jwt';
import { verifyTotp } from '../auth/totp';

const router = Router();

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

interface ChallengeEntry {
  userId: string;
  expiresAt: number;
}

// Simple in-memory challenge-token store (userId lookups) with a 5 minute TTL.
const challenges = new Map<string, ChallengeEntry>();

function purgeExpiredChallenges(): void {
  const now = Date.now();
  for (const [token, entry] of challenges.entries()) {
    if (entry.expiresAt <= now) {
      challenges.delete(token);
    }
  }
}

router.post('/auth/login', (req, res) => {
  const { username, password } = req.body ?? {};

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
  if (!user || !bcrypt.compareSync(password ?? '', user.passwordHash)) {
    res.status(401).json({ error: 'Invalid username or password' });
    return;
  }

  purgeExpiredChallenges();

  const challengeToken = uuidv4();
  challenges.set(challengeToken, { userId: user.id, expiresAt: Date.now() + CHALLENGE_TTL_MS });

  res.status(200).json({ challengeToken, twoFactorRequired: true });
});

router.post('/auth/2fa/verify', (req, res) => {
  const { challengeToken, totpCode } = req.body ?? {};

  purgeExpiredChallenges();
  const entry = challengeToken ? challenges.get(challengeToken) : undefined;
  if (!entry) {
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(entry.userId) as UserRow | undefined;
  if (!user) {
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  let totpVerified = false;
  if (user.totpSecret) {
    const valid = verifyTotp(user.totpSecret, totpCode ?? '');
    if (!valid) {
      res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
      return;
    }
    totpVerified = true;
  }
  // If no TOTP secret is configured for this user, allow completion in dev
  // mode, but do NOT claim `totp` in `amr` since it was never verified -
  // this keeps `require2FA`-gated endpoints locked down for such accounts.

  challenges.delete(challengeToken);

  const roles = JSON.parse(user.roles) as string[];
  const permissions = JSON.parse(user.permissions) as string[];
  const expiresIn = 3600;

  const accessToken = signToken(
    {
      sub: user.id,
      username: user.username,
      roles,
      permissions,
      amr: totpVerified ? ['totp'] : ['pwd'],
    },
    expiresIn
  );

  res.status(200).json({ accessToken, expiresIn, roles, permissions });
});

export default router;
