# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Latest

### Added

- Expanded cnf to contain correct structure while still providing the old one. Example:

```json
{
    "cnf": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "...",
            "y": "..."
        }
    }
}
```

- Breaking! updated url path to distinguish management (with `/management`) and oid4vci (with `/oid4vci`) urls
- Added new endpoint `/.well-known/oauth-authorization-server` that provides the same information as the
  `/.well-known/openid-configuration` endpoint but in a OAuth2-centric way.
- The `/.well-known/openid-configuration` still exists and is not deprecated.

- Added new endpoints for
  optional
  OID4VCI [deferred flow](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-deferred-credential-endpoin)
    - Changed the `/credential` to check if the request is marked as deferred in
      the `credentialMetadata` with `"deferred: true"`, which is set by the issuer-agent-management. The endpoint
      returns a transaction_id
      instead of a credential.
    - Added `/oid4vci/deferred-credential-request` to request deferred credential with the received transaction id
    - Added Documentation in the issuer-agent-management repository.
    - Added new credential request errors that are necessary for the deferred flow: ISSUANCE_PENDING,
      INVALID_TRANSACTION_ID

Example response of the credential endpoint `/credential` ("deferred: true") is:

```json
{
    "transaction_id": "b932ca39-0158-4a31-80e4-8aa15d9d987c",
    "c_nonce": "5585f3ba-e41f-4556-8182-bb148eb8c344"
}
```

Example payload of the request to deferred-credential endpoint`/deferred_credential` is:

```json
{
    "transaction_id": "b932ca39-0158-4a31-80e4-8aa15d9d987c",
    "proof": {
        "proof_type": "jwt",
        "jwt": "..."
    }
}
```

- Enable requesting Key Attestation via Issuer Metadata. This can be used with key_attestation_required. See readme for
  more details.
- Enable receiving and verification of Key Attestations in Credential Request Proofs. Verifying the integrity of the
  attestation and checking if it was issued by one of the issuers trusted in TRUSTED_ATTESTATION_PROVIDERS.
- Fixed incorrect error code when access token is wrong to INVALID_TOKEN instead of INVALID_CREDENTIAL.
- Expanded `/token` functionality. The endpoint accepts now `application/x-www-urlencoded` and no content-type.
  It still accepts the values in the url as request-params (this functionality will be removed in the future) and
  as `x-www-form-urlencoded` body.
- Credential Offer is now validated according to the published metadata. Additional 'surprise' claims are no longer supported.
- Optional OAuth security with bearer tokens on `/management` endpoints. 
  It can be activated and configured via spring environment variables.
### Fixed

- Checks for protected claims are now done in the create-offer-flow (1 step) instead of the issuance flow.
- Business Issuer is directly informed when the payload cannot be processed later.
- Fix status code when jwt filter criteria are not met from a 500 to 401.
- Fixed error code when deferred endpoint is called with invalid transaction id to INVALID_TRANSACTION_ID instead of
  INVALID_CREDENTIAL_REQUEST.

## 1.0.0

Merge of issuer-agent-management 1.6.1 and issuer-agent-oid4vci into one service.

For migration merge environment variables. Please ensure that management endpoints are not accessible from public using
a WAF or Reverse-Proxy limiting the reachable endpoints.

Note: If using HSM for signing, both status list and credentials must be signed with HSM.