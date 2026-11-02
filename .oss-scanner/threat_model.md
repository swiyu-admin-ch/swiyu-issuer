# Threat model: swiyu-issuer

## What the project is
The generic Issuer of the Swiss SWIYU trust infrastructure (https://github.com/swiyu-admin-ch/swiyu-issuer).
It is a Spring Boot 4 / Java 25 service (Maven, modules `issuer-service` and `issuer-application`) backed by PostgreSQL.
It issues verifiable credentials (SD-JWT VC) to wallets via OID4VCI (pre-authorized code flow, DPoP, nonces, key
attestation, deferred issuance, credential renewal), exposes a management API for the business system that
creates credential offers and manages their status, signs credentials with a configured key (key file or HSM using PKCS or JCA), maintains token status lists, and calls the swiyu registries (status, trust, identifier) and
webhook targets. Cryptographic and validation building blocks come from
swiyu-generic-java-lib (https://github.com/swiyu-admin-ch/swiyu-generic-java-lib); the counterpart that verifies
presentations is the swiyu-verifier (https://github.com/swiyu-admin-ch/swiyu-verifier).

## Where untrusted input enters
Public endpoints (no authentication filter; protection relies on offer/pre-authorized code, access token, nonce,
DPoP and proof-of-possession checks):
- `POST /oid4vci/api/token` (form-encoded, pre-authorized code grant, DPoP header)
- `POST /oid4vci/api/nonce`
- `POST /oid4vci/api/credential` (JSON or encrypted JWT body; proof JWTs, key attestations, DPoP, renewal requests)
- `POST /oid4vci/api/deferred_credential`
- `GET /oid4vci/vct/{key}`, `/oid4vci/json-schema/{key}`, `/oid4vci/oca/{key}` (credential metadata)
- `GET` well-known metadata: `/.well-known/openid-credential-issuer`, `/.well-known/openid-configuration`,
  `/.well-known/oauth-authorization-server` (including `{tenantId}` and `/oid4vci` path variants)
- `/actuator/**` (optional Basic Auth for `/actuator/prometheus`), Swagger UI and `/v3/api-docs`

Management endpoints (OAuth2 resource server with JWT or opaque token; if no OAuth property is configured the
chain is open by design for local use):
- `/management/api/credentials/**` (create offers with credential claims, read/update offer status, renewal)
- `/management/api/status-list/**` (create/read/update status lists)

Other inputs:
- Claims, metadata, JSON schemas and offer data supplied through the management API
- DID documents / DID logs, status list tokens and trust statements fetched from the registries
- Wallet-supplied JWTs: proof of possession, DPoP proofs, client/key attestations, JWE envelopes
- Content of the PostgreSQL database and the configuration (environment, signing key material)

## Ecosystem context (derived from the swiyu threat model)
Derived from the STRIDE-based attack trees of the swiyu trust infrastructure
(https://swiyu-admin-ch.github.io/threat-model/). Assumptions taken over: attackers are computationally bounded and
cannot break cryptographic primitives; TLS 1.3, the TEE, the operating system and the device are trustworthy.
Issuer-relevant branches:
- **1.7 Actor unavailable / 2.2.2 Malicious requests:** crafted requests to the public OID4VCI endpoints that crash the
  service or cause out-of-memory / CPU loops (oversized or deeply nested JSON/JWT/JWE, expensive validation).
- **2.2 / 2.2.1 Design flaws and supply chain, 2.2.4 Reach hidden/protected endpoints, 2.2.5 Insecure configuration:**
  management, actuator or documentation endpoints reachable without proper authentication; unsafe defaults or easy-to-misuse
  configuration; vulnerable or malicious dependencies when reachable from the issuer.
- **2.3 Unallowed change of swiyu managed content:** changing offers, offer status, status lists or credential metadata
  through the public API or by unintended access paths; integrity of stored state transitions.
- **2.4 Spoofing / 3.2.2 Impersonate legitimate issuer:** issuer identity (DID, signing key, published metadata) and trust of
  the communication partners (registries, webhook targets) must be validated.
- **3.2 Issue credential for attacker:** credentials must only be issued for a valid, unexpired, single-use offer to the
  intended holder; related **3.2.1 Steal credential offer** (pre-authorized code and optional transaction code must not be
  guessable, replayable or reusable) and **3.2.3 Impersonate holder** (holder binding, DPoP and nonce handling).
- **3.2.3.3 Exploit credential renewal flow:** renewal must not allow issuing a credential to a self-controlled wallet or
  for a revoked/expired/foreign credential.
- **3.2.4 Issue restricted schema:** an issuer/tenant must not be able to issue credential types it is not authorized for.
- **3.3 Change sent VC / 3.4 Change credential request:** tampering with a credential or request (e.g. removing the
  holder-binding requirement, altering claims, replaying proofs) must be detected and rejected.
- **4.1.1, 4.1.5, 4.4.1, 4.5 Privacy:** no leakage of holder or claim data via logs, errors, webhooks or metadata; no
  tracking identifiers beyond what the specification requires (e.g. status list index/URI); issuer does not learn more about
  holders than necessary.
- **5.x Non-repudiation:** issuance and status changes should leave a reliable trace.

Cryptographic primitives, JWT/SD-JWT/DPoP validation and DID resolution are implemented in swiyu-generic-java-lib;
this repository is responsible for using them correctly.

## Security goals / what we care about (draft, to be confirmed by the security team)
- No credential is issued to an unauthorized party; offers are single-use, expire, and are bound to the holder key.
- Nonce, DPoP, proof-of-possession and key-attestation checks cannot be bypassed or replayed.
- The management API cannot be used without authentication when authentication is configured; no access to other
  tenants' or other offers' data (IDOR, path/ID manipulation).
- Credential content and status cannot be altered after issuance without detection; status lists stay consistent.
- Resource exhaustion from small attacker-controlled inputs on public endpoints.
- No leakage of signing keys, holder data or PII via logs, error messages, metadata or webhooks.
- Safe handling of untrusted JSON, JSON schemas, claims path expressions and outbound HTTP calls (e.g. SSRF to non-allowed hosts).

## Severity guidance (draft, to be confirmed by the security team)
- Critical: credential issued to an unauthorized party or with forged content; authentication bypass on the management API;
  disclosure of signing key material.
- High: replay/theft of offers, tokens or nonces leading to issuance; cross-offer/tenant data access; denial of service
  from a small unauthenticated request; leakage of holder data.
- Medium: missing size/rate limits, incorrect error handling or state transitions with limited impact; information
  disclosure of non-sensitive internal details.
- Low: hardening issues without a demonstrated exploit.

## Out of scope
- Test code, build scripts, CI configuration, documentation and example files.
- Wallet and device topics (key storage, backup, recovery, phishing of the holder, physical access), attestation and
  push notification services.
- External services (registries, DNS, identity provider, cloud/hosting infrastructure) and their availability.
- Social engineering and organisational topics (support, internal leaks, access management, backups, operations).
- Verifier-side issues (see https://github.com/swiyu-admin-ch/swiyu-verifier) and flaws inside swiyu-generic-java-lib
  (report in https://github.com/swiyu-admin-ch/swiyu-generic-java-lib), unless caused by incorrect use in this repository.
- Vulnerabilities in third-party dependencies without a reachable path from the issuer.
- Misconfiguration by the operator, including running the management API without OAuth configuration.
