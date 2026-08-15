import { Request, Response } from 'express';
import { db } from '../db';
import { decrypt } from '../utils/crypto';

export function internalRouter() {
  const router = require('express').Router();

  // Middleware to authenticate plugins
  const pluginAuth = (req: Request, res: Response, next: (err?: any) => void) => {
    const apiKey = req.headers['x-plugin-api-key'];
    if (apiKey !== process.env.PLUGIN_API_KEY) {
      return res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    }
    next();
  };

  router.get('/secrets/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      const result = await db.query.secrets.findFirst({
        where: (secrets, { eq }) => eq(secrets.id, id),
      });
      if (!result) {
        return res.status(404).json({ error: 'Secret not found' });
      }
      const encryptedValue = result.encryptedValue;
      const decryptedValue = decrypt(encryptedValue);
      
      // We return the secret as a JSON object. 
      // In a real system, we'd store the secret as a JSON string in the encryptedValue.
      // For now, we'll assume the encryptedValue is a JSON string of { apiKey: string, apiSecret: string }
      const secret = JSON.parse(decryptedValue);
      res.json(secret);
    } catch (error) {
      console.error('Error retrieving secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}