import type { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { loadAuthConfig, validateAuthConfig } from './config';
import { AuthError } from './errors';
import { verifyToken } from './tokens';
import type { AuthConfigInput } from './types';

export function createAuthMiddleware(
  config: AuthConfigInput = loadAuthConfig(),
): RequestHandler {
  const validated = validateAuthConfig(config);
  return (req, res, next) => {
    delete req.auth;
    const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') || '');
    if (!match) {
      res.set('WWW-Authenticate', 'Bearer');
      return next(new AuthError(401, 'UNAUTHORIZED', 'A bearer token is required.'));
    }
    try {
      req.auth = verifyToken(match[1], validated);
    } catch (error) {
      if (!(error instanceof jwt.JsonWebTokenError)) {
        return next(error);
      }
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      return next(new AuthError(401, 'UNAUTHORIZED', 'The bearer token is invalid or expired.'));
    }
    next();
  };
}
