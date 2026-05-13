# eunomia-infrastructure

> **Cross-cutting infrastructure for the Eunomia stack — Keycloak, OpenMetadata, MySQL, Elasticsearch, Qdrant, and the Phase D verification harness.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`docker-compose.yml` brings up all the bottom-of-stack services the Eunomia middleware depends on. The Keycloak realm is seeded from `keycloak/realm-export.json` so any developer gets the same users, roles, clients, and policies without manual UI clicks. The `verify_phase_d.py` script asserts the entire identity → authorization → execution → audit chain end-to-end against the live stack .

---

## What's in the box

| Service | Image | Port | Purpose |
|---|---|---|---|
| Keycloak | `quay.io/keycloak/keycloak:24.0.0` | `8080` | OIDC identity provider for users + the RAG indexer service account |
| OpenMetadata server | `docker.getcollate.io/openmetadata/server:1.12.6` | `8585` | Catalog + tag-policy decision point |
| OM MySQL (Elastic backing store) | `docker.getcollate.io/openmetadata/db:1.12.6` | `3307` | OM's own data store (not the analytics warehouse) |
| Elasticsearch | `docker.elastic.co/elasticsearch/elasticsearch:9.3.0` | `9200` | OM's search index |

The Eunomia *analytics* MySQL warehouse runs on `localhost:3306` and is not managed by this compose — it pre-existed and is expected to already host the seeded views.

Qdrant is brought up from `eunomia-rag/docker-compose.yml` (it's owned by the RAG service repo).

---

## Layout

```
eunomia-infrastructure/
├── docker-compose.yml             keycloak + openmetadata + om-mysql + elasticsearch
├── openmetadata.yml               legacy OM-only compose (kept for back-compat)
├── keycloak/
│   ├── realm-export.json          eunomia realm — roles, clients, users, claim mappers
│   └── README.md                  bring-up, seeded contents, verification, reset runbook
├── openmetadata/
│   └── env.openmetadata           OIDC env vars OM consumes (custom-oidc mode)
├── verify_phase_d.py              30-case end-to-end verification harness
└── LICENSE
```

Companion repos:
- [`eunomia-middleware`](https://github.com/anuj81/eunomia-middleware) — governance NLQ engine
- [`eunomia-rag`](https://github.com/anuj81/eunomia-rag) — catalog-aware relevance ranker
- [`eunomia-cli`](https://github.com/anuj81/eunomia-cli) — Device Code login + `ask` command

---

## Quickstart

```bash
# 1. Bring up Keycloak + OpenMetadata + ES + OM-MySQL
docker-compose up -d

# 2. Verify the realm imported (≈10s after start)
curl -s http://localhost:8080/realms/eunomia/.well-known/openid-configuration | jq .issuer
# → "http://localhost:8080/realms/eunomia"

# 3. Open the Keycloak admin console (admin / admin)
open http://localhost:8080

# 4. Open OpenMetadata (after ~90s warm-up)
open http://localhost:8585

# 5. Tear down — keep volumes
docker-compose down

# 6. Tear down + wipe state (re-imports realm on next up)
docker-compose down -v
```

After the infra is up, follow the per-repo quickstarts in `eunomia-middleware`, `eunomia-rag`, and `eunomia-cli`.

---

## Seeded Keycloak realm

`keycloak/realm-export.json` is the source of truth. Highlights:

### Realm

- **Name**: `eunomia`
- **Issuer**: `http://localhost:8080/realms/eunomia`
- **Access token lifespan**: 1h (dev convenience)
- Hostname pinned via `KC_HOSTNAME=localhost` so JWT `iss` is stable across reachers (host shell, OM container, middleware), avoiding the `http://keycloak:8080/...` mismatch when OM verifies signatures backchannel.

### Roles

| Role | Effect |
|---|---|
| `eunomia-finance-user` | Read access to Finance domain views |
| `eunomia-external-auditor` | Read access to payment-history view only |
| `eunomia-marketing-lead` | Read access to Marketing domain views |
| `eunomia-agency-partner` | Agency-safe Marketing views only |
| `eunomia-om-admin` | Catalog admin — sees ALL incl. gold base tables |
| `eunomia-pii-unmask` | Compositional — grants PII unmasked view of results |

### Clients

| Client ID | Type | Grants |
|---|---|---|
| `eunomia-cli` | Public | Device Code + Direct Access (for tests) |
| `eunomia-middleware` | Public, bearer-only | (token validation only) |
| `openmetadata` | Confidential | Authorization Code (for OM SSO) |
| `eunomia-rag-indexer` | Confidential | Client Credentials (service account for the indexer) |

The RAG indexer's service-account user (`service-account-eunomia-rag-indexer`) holds `eunomia-om-admin` so its `client_credentials` tokens see the full OpenMetadata catalog. Hardcoded-claim mappers ensure those tokens carry `preferred_username` and `email` so OM can resolve the service-account to its corresponding OM user record.

### Test users

All passwords: `test` (development only — do not run this realm outside a dev box).

| Username | Realm roles |
|---|---|
| `finance.alice` | `eunomia-finance-user`, `eunomia-pii-unmask` |
| `auditor.bob` | `eunomia-external-auditor` |
| `marketing.carol` | `eunomia-marketing-lead`, `eunomia-pii-unmask` |
| `agency.dave` | `eunomia-agency-partner` |
| `om.admin` | `eunomia-om-admin`, `eunomia-pii-unmask` |

---

## OpenMetadata SSO

`openmetadata/env.openmetadata` configures OM in `custom-oidc` mode:

```
AUTHENTICATION_PROVIDER=custom-oidc
AUTHENTICATION_AUTHORITY=http://localhost:8080/realms/eunomia   (matches JWT 'iss')
AUTHENTICATION_PUBLIC_KEY_URLS=[http://eunomia_keycloak:8080/realms/eunomia/protocol/openid-connect/certs]
AUTHENTICATION_CLIENT_ID=openmetadata
AUTHENTICATION_JWT_PRINCIPAL_CLAIMS=[email,preferred_username]
AUTHORIZER_ADMIN_PRINCIPALS=[admin,om.admin]
```

> **Note**: OpenMetadata 1.12 persists the runtime auth config in its database (`openmetadata_settings` table). The env file is only the bootstrap default. To change the runtime config in an already-deployed OM, you have to UPDATE the JSON in that row directly. See `eunomia-middleware/seed_om_policies.py` for the policy seeding that runs on top of this auth setup.

---

## End-to-end verification

`verify_phase_d.py` runs against the live stack and prints a PASS/FAIL summary table. **Exit 0** means every assertion in the Phase D trust line holds.

```bash
# Requires Keycloak + OM + Qdrant + MySQL + middleware + RAG service all up
python verify_phase_d.py

# Sample output:
#   === 1. Preflight ===
#     ✓ Keycloak realm discovery
#     ✓ OpenMetadata /healthcheck
#     ✓ Qdrant /healthz
#     ✓ Middleware /docs
#     ✓ RAG /v1/healthz
#     ✓ MySQL :3306 reachable
#   === 2. Identity (Keycloak token grant + role claim) ===
#     ✓ finance.alice: token + expected roles
#     ...
#   === 3. OpenMetadata tag-policy authorization ===
#     ✓ auditor.bob: OM tag search returns expected views
#     ...
#   === 4. Middleware NLQ flow (SSE) ===
#     ✓ marketing.carol: NLQ → 'Found 2 Allowed Views'
#     ...
#   === 5. Adversarial — bad / missing / tampered tokens ===
#     ✓ No bearer header → 401
#     ✓ Gibberish bearer → 401
#     ✓ Tampered signature → 401
#     ✓ Wrong issuer in claims → 401
#   === 6. PII masking matrix (via audit log inspection) ===
#     ✓ om.admin: audit.unmask_pii matches role
#     ...
#   ======================================================================
#   TOTAL: 30/30  PASS
```

Flags:

```
python verify_phase_d.py --skip-nlq   # skip the LLM-dependent NLQ section
python verify_phase_d.py --quiet      # only print the summary
```

The harness is also surfaced as `eunomia-cli admin verify` (which prints this runbook).

---

## Sequence diagram

The full Phase 1 + Phase D sequence (Keycloak → middleware → OM → RAG → LLM → MySQL → PII → audit) is in [planning/middleware_architecture.md](../planning/middleware_architecture.md) §2 of the planning docs.

---

## Security notes (dev only)

- The seeded realm hardcodes admin / user passwords and client secrets — **dev only**.
- `start-dev` runs Keycloak in HTTP, with development safety checks disabled.
- The OM bootstrap env file points OM at OIDC; the runtime auth config persists in OM's database. Resetting via `docker-compose down -v` wipes that state.
- The `verify_phase_d.py` harness reads tokens via password grant against test users — convenient for testing but you wouldn't expose Direct Access Grant on a production realm.

For production, this repo would need: TLS termination at all endpoints, externally-issued client secrets, removed test-user direct grants, a real OM admin password rotation policy, persistent volume backups, and a NOTICE for the open-source components packaged in it.

---

## License

[Apache 2.0](LICENSE)
