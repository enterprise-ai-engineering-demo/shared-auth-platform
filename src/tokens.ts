import jwt from 'jsonwebtoken';
import { loadAuthConfig, validateAuthConfig } from './config';
import type { AuthClaims, AuthConfigInput, TokenInput, TokenOptions } from './types';

export function isRoleList(value: unknown): value is string[] {
  return Array.isArray(value) &&
    value.every((role) => typeof role === 'string' && role.trim().length > 0);
}

export function generateToken(
  input: TokenInput,
  config: AuthConfigInput = loadAuthConfig(),
  { expiresIn = '1h' }: TokenOptions = {},
): string {
  const { secret, issuer, audience } = validateAuthConfig(config);
  if (typeof input.subject !== 'string' || !input.subject.trim()) {
    throw new TypeError('Token subject must be a non-empty string.');
  }
  if (input.roles !== undefined && !isRoleList(input.roles)) {
    throw new TypeError('Token roles must be an array of non-empty strings.');
  }
  const payload = input.roles === undefined ? {} : { roles: input.roles };
  return jwt.sign(payload, secret, {
    algorithm: 'HS256',
    subject: input.subject,
    issuer,
    audience,
    expiresIn,
  });
}

export function verifyToken(
  token: string,
  config: AuthConfigInput = loadAuthConfig(),
): AuthClaims {
  const { secret, issuer, audience } = validateAuthConfig(config);
  const claims = jwt.verify(token, secret, {
    algorithms: ['HS256'],
    issuer,
    audience,
  });
  if (typeof claims === 'string' ||
      (claims.roles !== undefined && !isRoleList(claims.roles))) {
    throw new jwt.JsonWebTokenError('Invalid authentication claims.');
  }
  return claims;
}
