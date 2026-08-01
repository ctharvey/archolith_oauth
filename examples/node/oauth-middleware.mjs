import { createRemoteJWKSet, jwtVerify } from 'jose';

function scopesFromPayload(payload) {
  const scopes = new Set();
  for (const key of ['scope', 'scp', 'permissions']) {
    const raw = payload[key];
    if (typeof raw === 'string') {
      for (const scope of raw.split(/\s+/)) if (scope) scopes.add(scope);
    } else if (Array.isArray(raw)) {
      for (const scope of raw) if (scope) scopes.add(String(scope));
    }
  }
  return scopes;
}

export function createTokenVerifier({ issuer, audience, jwksUri }) {
  const jwks = createRemoteJWKSet(new URL(jwksUri));

  return async function verifyAuthorization(
    authorization,
    { requiredScopes = [], anyScopes = [] } = {},
  ) {
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
      const error = new Error('Missing bearer token');
      error.code = 'invalid_token';
      error.statusCode = 401;
      throw error;
    }

    const token = authorization.slice(7).trim();
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer,
      audience,
      algorithms: ['RS256'],
      requiredClaims: ['exp'],
    });
    const scopes = scopesFromPayload(payload);

    const missing = requiredScopes.filter(scope => !scopes.has(scope));
    const hasAny = anyScopes.length === 0 || anyScopes.some(scope => scopes.has(scope));
    if (missing.length > 0 || !hasAny) {
      const error = new Error('Access token has insufficient scope');
      error.code = 'insufficient_scope';
      error.statusCode = 403;
      error.requiredScopes = [...new Set([...requiredScopes, ...anyScopes])];
      throw error;
    }

    return {
      subject: String(payload.sub || ''),
      clientId: String(payload.client_id || payload.azp || ''),
      clientName: String(payload.client_name || ''),
      scopes,
      claims: payload,
      protectedHeader,
    };
  };
}

export function expressOAuthMiddleware({
  verifyAuthorization,
  requirementFor = () => ({ requiredScopes: [], anyScopes: [] }),
  resourceMetadataUrl,
}) {
  return async function oauthMiddleware(req, res, next) {
    const requirement = requirementFor(req) || {};
    try {
      req.oauth = await verifyAuthorization(req.headers.authorization, requirement);
      return next();
    } catch (error) {
      const status = Number(error.statusCode) || 401;
      const challenge = [
        `Bearer resource_metadata="${resourceMetadataUrl}"`,
        `error="${error.code || 'invalid_token'}"`,
      ];
      if (error.requiredScopes?.length) {
        challenge.push(`scope="${error.requiredScopes.join(' ')}"`);
      }
      res.setHeader('WWW-Authenticate', challenge.join(', '));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(status).json({
        error: error.code || 'invalid_token',
        error_description: error.message,
      });
    }
  };
}

// Harness example:
//
// const verifyAuthorization = createTokenVerifier({
//   issuer: 'https://auth.ctharvey.me/harness',
//   audience: 'https://harness.ctharvey.me/mcp',
//   jwksUri: 'https://auth.ctharvey.me/harness/.well-known/jwks.json',
// });
// app.use('/mcp', expressOAuthMiddleware({
//   verifyAuthorization,
//   resourceMetadataUrl:
//     'https://harness.ctharvey.me/.well-known/oauth-protected-resource/mcp',
//   requirementFor: req => ({
//     requiredScopes: req.body?.params?.name?.startsWith('harness_delete_')
//       ? ['harness:admin']
//       : ['harness:read'],
//   }),
// }));
//
// Never copy req.headers.authorization into OpenCode, provider config, logs, or
// child-process environments. Only the verified req.oauth principal is trusted.
