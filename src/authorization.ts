import type { RequestHandler } from 'express';
import { AuthError } from './errors';
import { isRoleList } from './tokens';
import type { AuthClaims } from './types';

export function hasRole(claims: AuthClaims | undefined, role: string): boolean {
  return isRoleList(claims?.roles) && claims.roles.includes(role);
}

/** Allows any one of the specified roles; an empty policy is a configuration error. */
export function requireRoles(...roles: string[]): RequestHandler {
  if (roles.length === 0 || !isRoleList(roles)) {
    throw new TypeError('At least one non-empty role is required.');
  }
  return (req, _res, next) => {
    if (!req.auth) {
      return next(new AuthError(401, 'UNAUTHORIZED', 'Authentication is required.'));
    }
    if (!roles.some((role) => hasRole(req.auth, role))) {
      return next(new AuthError(403, 'FORBIDDEN', 'Insufficient permissions.'));
    }
    next();
  };
}
