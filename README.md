# archolith-oauth

Reusable OAuth 2.1 building blocks extracted from Menhir for Archolith services and remote MCP protected resources.

## Included

- OAuth protected-resource and authorization-server metadata builders
- Dynamic client registration validation for public PKCE clients
- Authorization request validation and scope narrowing
- SQLite registered-client and single-use authorization-code stores
- RFC 7636 PKCE helpers
- Persistent RS256 signing-key storage behind a JOSE seam
- Access-token issuance and JWT/JWKS verification
- Generic principals and scopes with no Menhir-specific tier policy

## Deliberate boundaries

This package does **not** provide a login or consent UI, service-specific scope mapping, HTTP framework middleware, or refresh tokens yet. Applications own those policy and presentation layers.

## Example

```python
from pathlib import Path
from archolith_oauth import (
    AuthorizationServerConfig,
    SigningKeyStore,
    TokenIssuer,
)

config = AuthorizationServerConfig(
    issuer="https://auth.example.com",
    resource="https://service.example.com/mcp",
    scopes_supported=("service:read", "service:write"),
)
key_store = SigningKeyStore(Path("oauth-signing-key.json"))
issuer = TokenIssuer(config, key_store.load_or_create())
```

## Migration target

Menhir should retain its consent screen, environment mapping, and scope-to-tier policy while importing the protocol core from this package. `cth.harness` can then use the same package through a small Python auth gateway or a language-neutral JWT verification boundary.
