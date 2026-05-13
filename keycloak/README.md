# Keycloak — Eunomia realm

Identity provider for the Eunomia stack. Bring-up imports the `eunomia` realm
from `realm-export.json` so every dev gets the same users, roles, and clients
without manual UI clicks.

## Quick start

```bash
cd ..    # eunomia-infrastructure/
docker-compose up -d keycloak

# Admin console (user `admin`, password `admin`):
#   http://localhost:8080

# OIDC discovery for the eunomia realm:
#   http://localhost:8080/realms/eunomia/.well-known/openid-configuration
```

Keycloak starts in dev mode (`start-dev`, `KC_DB=dev-file`). Suitable for
local development only; do not deploy this image in production.

## Seeded contents

### Realm
- **Name**: `eunomia`
- **Issuer**: `http://localhost:8080/realms/eunomia`
- **Access token lifespan**: 1h (dev convenience)

### Realm roles
| Role | Purpose |
|---|---|
| `eunomia-finance-user`     | Read access to Finance domain views |
| `eunomia-external-auditor` | Read access to payment-history; PII masked |
| `eunomia-marketing-lead`   | Read access to Marketing domain views |
| `eunomia-agency-partner`   | Agency-safe Marketing views only |
| `eunomia-om-admin`         | Catalog admin — sees ALL incl. gold base tables |
| `eunomia-pii-unmask`       | Compositional — grants PII-unmasked view of results |

### Clients
| Client ID | Type | Grants enabled |
|---|---|---|
| `eunomia-cli`         | Public | Device Code + Direct Access (for tests) |
| `eunomia-middleware`  | Public, bearer-only | (validation only — no flows) |
| `openmetadata`        | Confidential (secret: `openmetadata-client-secret`) | Authorization Code (for OM SSO) |
| `eunomia-rag-indexer` | Confidential (secret: `rag-indexer-client-secret`) | Client Credentials only |

### Test users
All passwords: **`test`**

| Username | Realm roles |
|---|---|
| `finance.alice`   | `eunomia-finance-user`, `eunomia-pii-unmask` |
| `auditor.bob`     | `eunomia-external-auditor` |
| `marketing.carol` | `eunomia-marketing-lead`, `eunomia-pii-unmask` |
| `agency.dave`     | `eunomia-agency-partner` |
| `om.admin`        | `eunomia-om-admin`, `eunomia-pii-unmask` |

The RAG indexer's service-account user (`service-account-eunomia-rag-indexer`)
holds `eunomia-om-admin` so its `client_credentials` tokens see the full
OpenMetadata catalog.

## Verification

```bash
# Discovery doc reachable
curl -s http://localhost:8080/realms/eunomia/.well-known/openid-configuration \
    | python3 -m json.tool | head -10

# JWKS reachable
curl -s http://localhost:8080/realms/eunomia/protocol/openid-connect/certs \
    | python3 -c "import sys,json; print('Keys:', len(json.load(sys.stdin)['keys']))"

# Get a token for finance.alice via password grant
TOKEN=$(curl -s -X POST \
    http://localhost:8080/realms/eunomia/protocol/openid-connect/token \
    -d "client_id=eunomia-cli" \
    -d "grant_type=password" \
    -d "username=finance.alice" \
    -d "password=test" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Decode the payload (no signature verification)
python3 -c "
import base64, json, sys
payload = '$TOKEN'.split('.')[1]
payload += '=' * (-len(payload) % 4)
d = json.loads(base64.urlsafe_b64decode(payload))
print('preferred_username:', d.get('preferred_username'))
print('email             :', d.get('email'))
print('realm_access.roles:', d.get('realm_access', {}).get('roles', []))
"
```

## Reset

The realm import is idempotent — re-importing on an existing realm is a no-op.
To wipe and start fresh:

```bash
docker-compose down -v   # NB: -v also wipes openmetadata and elasticsearch volumes
docker-compose up -d keycloak
```

Or to reset Keycloak alone:

```bash
docker-compose stop keycloak
docker-compose rm -f keycloak
docker volume rm eunomia-infrastructure_kc-data 2>/dev/null || true
docker-compose up -d keycloak
```

(The dev-file backend stores state inside the container's filesystem; removing
the container is enough to wipe Keycloak without touching OM/MySQL data.)

## Known-knowns

- **Audience claim is empty.** Keycloak does not include the requesting client_id
  in `aud` by default — it uses `azp` instead. If a downstream service (e.g.
  OpenMetadata's OIDC validator) insists on a specific `aud` claim, add an
  Audience protocol mapper via a client scope (`aud-openmetadata`,
  `aud-eunomia-middleware`) and attach it as a default scope to `eunomia-cli`.
  Not done preemptively — we'll add it if/when D.1's verification gate trips on it.

## Security notes (dev only!)

- Admin password is `admin` and test users all share password `test`.
- Client secrets are committed in `realm-export.json` for reproducibility.
- `start-dev` is HTTP-only and disables many production safety checks.

None of these are acceptable in any non-dev environment. The realm export
should be treated as a *shape definition*, not a deployable secret bundle.
