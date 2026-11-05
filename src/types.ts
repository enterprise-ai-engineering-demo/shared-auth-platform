import type { JwtPayload, SignOptions } from 'jsonwebtoken';

export interface AuthConfig {
  secret: string;
  issuer: string;
  audience: string;
}

export interface AuthConfigInput {
  secret?: string;
  issuer?: string;
  audience?: string;
}

export interface AuthClaims extends JwtPayload {
  roles?: string[];
}

export interface TokenInput {
  subject: string;
  roles?: string[];
}

export interface TokenOptions {
  expiresIn?: SignOptions['expiresIn'];
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthClaims;
    }
  }
}
