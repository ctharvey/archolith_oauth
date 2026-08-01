# archolith-oauth

Reusable OAuth 2.1 building blocks extracted from Menhir for Archolith services and remote MCP protected resources.

## Included

- RFC 9728 protected-resource and RFC 8414 authorization-server metadata
- Path-aware `.well-known` discovery for issuers/resources with URL paths
- Dynamic client registration for public PKCE clients
- Exact redirect, scope, and RFC 8707 resource validation
- Menhir-compatible SQLite client and single-use authorization-code stores
- Persistent RS256 signing keys behind a JOSE seam
- Access-token issuance and JWT/JWKS verification
- Opt-in `offline_access` with rotating, replay-detecting refresh tokens
- Generic principals and scopes with no service-specific tier policy

## Deliberate boundaries

Applications still own their login/consent UI, HTTP framework routes and middleware, rate limits, user identity, and service-specific scope policy.

## Example

```python
from pathlib import Path
from archolith_oauth import AuthorizationServerConfig, SigningKeyStore, TokenIssuer

config = AuthorizationServerConfig(
    issuer="https://auth.example.com/harness",
    resource="https://harness.example.com/mcp",
    scopes_supported=("harness:read", "harness:session", "harness:admin"),
    default_scopes=("harness:read", "harness:session"),
    issue_refresh_tokens=True,
)
key = SigningKeyStore(Path("oauth-signing-key.json")).load_or_create()
issuer = TokenIssuer(config, key)
```

The client must send the same canonical `resource` value in both the authorization request and token request. Access tokens are audience-bound to that resource. `offline_access` is advertised when refresh tokens are enabled but is granted only when the client requests it.

For the example above, discovery URLs are:

- Authorization server: `https://auth.example.com/.well-known/oauth-authorization-server/harness`
- Protected resource: `https://harness.example.com/.well-known/oauth-protected-resource/mcp`

## Menhir adoption

Menhir keeps its existing settings adapter, consent screen, rate limits, singleton wiring, and `menhir:*` scope-to-tier mapping. The package preserves Menhir's current client database columns, client-store operations, and keyword-based authorization-code issuance, so migration can retain the existing `menhir_oauth_as.db`. Refresh tokens remain disabled unless Menhir explicitly enables them.

Menhir's authorize and token routes must begin requiring the same canonical `resource` value before switching to this package; this is stricter than its current implementation and is required by remote MCP authorization.

## Harness adoption

`cth.harness` remains Node.js. A small Python authorization service uses this package to perform registration, consent, token issuance, and refresh rotation. The Node MCP server validates the resulting JWT against the service's JWKS, issuer, audience, and `harness:*` scopes; it must not forward the inbound token to OpenCode or other providers.

Recommended scopes:

- `harness:read` — inspect sessions, output, status, and diffs
- `harness:session` — create and continue isolated sessions
- `harness:admin` — destructive session/worktree administration

Menhir and Harness should use separate `AuthorizationServerConfig` instances and resource audiences. They may share a host, but should use distinct issuer paths or separate authorization-server deployments.
