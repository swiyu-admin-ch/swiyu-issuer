# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

-- Set credential mgmt id in offer table

## Latest

### Added

- New endpoint `/actuator/env` to retrieve configuration details.
- New endpoint `/management/api/credentials/{credentialManagementId}/offers/{offerId}` to retrieve offer specific
  information.
- New endpoint `/management/api/credentials/{credentialManagementId}/offers/{offerId}/status` to retrieve the status of
  the offer.
- Send callback on every credential offer status change.
- Send callback on every credential management status change.
- Added field `event_trigger` to callback request
    - Field is set to `CREDENTIAL_MANAGEMENT` on credential management status change.
    - Field is set to `CREDENTIAL_OFFER` on credential offer status change.
- Allow setting the used Database Schema with environment variable `POSTGRES_DB_SCHEMA`. Default remains public as
  before.
- Updated Batch Issuance logic:
    - Min batch size must be 10 in metadata to improve privacy
    - If wallet sends fewer proofs than requested, the issuer will return a vc for every proof provided and will not
      throw an error.
- Added health checks for:
    - stale callbacks
    - Registry token getting refreshed
    - Status List availability
- Support `configuration_override` in `POST /management/api/status-list/{statusListId}` to control key material 
  selection (e.g., HSM key) during status list publication.
- Persist status list `configuration_override` updates via `POST /management/api/status-list/{statusListId}` 
  so the updated override is used for subsequent publications (also usable when automatic status list synchronization 
  is enabled).
- Swiss Profile versioning support for future version detection via `profile_version`.
    - Issuer metadata includes `profile_version` in unsigned JSON body and in signed JWT header.
    - SD-JWT VC includes `profile_version` in JWT header.
    - Status list tokens include `profile_version` in JWT header.
    - New environment variable `APPLICATION_SWISS_PROFILE_VERSIONING_ENFORCEMENT` (default: false) to optionally enforce `profile_version` checks for incoming JWT-based artifacts (e.g. DPoP and key attestations).

### Fixed

- Fixed weak unlinkability by rounding down the timestamps within issued credetials.
  Affected fields are iat, epx, and nbf.
- Removed credential request errors ISSUANCE_PENDING to be aligned with the spec.
- Fixed signed metadata using always the first key used, even when keys were rotated by issuers during renewals.- Deferred credential response when credential data is not ready is now 202 ACCEPTED
- Deferred credential transaction_id will not change anymore during deferred flow
- Added `deferred_credential_endpoint` and `batch_credential_issuance` with min batch size of 10 to sample.compose.yml

### Changed
- Removed the obsolete "version" tag from SD-JWT payloads, Status List tokens, Credential Offer data, and Issuer Metadata to align with the current specification.

## 2.3.1

### Fixed

- Allow encryption to be used for deferred credential request
- Allow wallets changing the deferred credential request encryption key using credential_response_encryption
- When using signed metadata with generates dynamic tenant ids, the tenant id is now automatically added to the
  credential issuer identifiers

## 2.3.0

### Added

- Added optional support for DPoP for wallets to begin adopting DPoP for more secure communication.
  As operator of an issuer there is action needed. This feature is added automatically.
  Note: In the future this will be enforced
- Implemented Refresh Flow as Draft implementation according spez. Should not yet used in production (#292)
- Integrated Spring State Machine for credential offer and management lifecycles, improving state management and error
  handling (#292).
- Added option to disable/enable refresh_token rotation after usage (#464).
- Added test coverage for signed metadata usage and renewal flow (#200, #292).

### Fixed

- Fixed missing alg field in JWKS keys for metadata endpoint (#597).
- Corrected subject claim in signed metadata and improved metadata endpoint to prefer signed data (#570).
- Fixed size limitations for incoming token calls and responses (#363).
- Fixed edge case with ephemeral signing keys causing server errors (#426).
- Fixed logs displaying management id incorrectly.
- Fixed tests and improved code for signed metadata (#570, #597).
- Fixed response size limitation for token calls (#363).
- Fixed error handling for credential requests missing JWT proof (#425).
- Fixed IT tests for RFC6749 compliance (#504).

## 2.2.0

### Added

- New public service methods to support renewal
    - Renewal uses the existing functionality of issuing a new credential
    - The change introduces a new state machine with different states for offers and the management of offers
    - New env variables:
        - `RENEWAL_FLOW_ENABLED` (default: false) to enable the renewal functionality
        - `BUSINESS_ISSUER_RENEWAL_API_ENDPOINT`: (no default) to set the renewal endpoint where the offer data can be
          fetched from
- Added possibility to update status list manually and disable the automatic synicnhronization.
  New environment variable `DISABLE_STATUS_LIST_SYNCHRONIZATION` (default: false) to disable automatic updates.
  New endpoint `/management/api/status-list/{statusListId}` to trigger manual update of a status list.
- Added support for OAuth 2.0 refresh_token. These are active by default and can be deactivated using the environment
  variable `ALLOW_TOKEN_REFRESH=false`. Only access_tokens belonging to a REVOKED offer can not be refreshed.
- Added new endpoints for signed metadata. The functionality is disabled by default at the moment and can be
  enabled by setting the environment variable `ENABLE_SIGNED_METADATA=true`. This will generate a deeplink with an
  additional tenant id.
    - Added new endpoint `/.well-known/openid-credential-issuer-signed-metadata` which provides signed metadata
      according to the OID4VCI spec.
    - Added new endpoint `/management/api/credentials/{credentialId}/signed-metadata` to provide signed
      credential-offer-metadata for a specific credential offer.
- Batch issuance now supports multiple indexes, preventing linkability through status list index.
  The used status list indexes are selected at random from remaining free indexes in status list.
- Updated didresolver dependency from 2.1.3 to 2.3.0

## 2.1.1

### Added

- Added new `vct_metadata_uri`, `vct_metadata_uri#integrity` fields to CredentialOfferMetadataDto which are then added
  to the credential claims
- Added WebhookCallbackDto to openapi config schemas.
- Added new environment variable `URL_REWRITE_MAPPING` to allow rewriting of URLs to support the check of
  key-attestation
- Added `key_attestations` to `CredentialInfoResponseDto.java` to support key attestations in the deferred
  credential flow.
  the credential request.
- Expanded the credential endpoint to accept the new credential-endpoint (with corresponding response)
  defined [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint),
  and the deferred credential endpoint which is
  defined [here](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin).
  These endpoints can be used by setting the custom header `SWIYU-API-Version=2`. These endpoints are not yet pentested.
- Added new error code `CREDENTIAL_REQUEST_DENIED` to indicate that the credential request was denied by the
  issuer and the wallet should not retry.
- Added always available Credential Request Payload encryption, can be enforced to be always active by setting
  APPLICATION_ENCRYPTIONENFORCE=true. Overriding will break compatibility with wallets not supporting encryption.

### Changed

- Changed the `didresolver` version from 2.0.1 to 2.1.3.
- Updated ApiErrorDto and reused it for every error response. This allows for a more consistent error
  response structure.
- Rename of
    - `CreateCredentialRequestDto` to `CredentialEndpointRequestDto` (without dto in openapi schema name)
    - `CredentialRequestDtoV2` to `CredentialEndpointRequestDtoV2` (without dto in openapi schema name)
    - `CredentialResponseDto` to `CredentialEndpointResponseDto` (without dto in openapi schema name)
    - `CredentialResponseDtoV2` to `CredentialEndpointResponseDtoV2` (without dto in openapi schema name)
      to fix inconsistent openapi definition.
- Allow nonce endpoint to be set freely like other endpoints. Not setting the nonce endpoint will prevent you form
  issuing credentials bound to a holder.

### Fixed

- Fixed offers in status `DEFERRED` or `READY` expire when the `offer_expiration_timestamp` has passed.
- `SWIYU_STATUS_REGISTRY_AUTH_ENABLE_REFRESH_TOKEN_FLOW` is now in the application.yaml set to true, as advertised as
  default behaviour in the readme.

### Removed

- Removed possibility of customization of payload encryption.
  It is now always possible for the wallet to choose payload encryption.

## 2.0.0

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

- Breaking! Refactored the getCredentialOffer endpoint which now returns all the credential offer information (but not
  the offer data, which is not needed)
    - Deprecated the getCredentialOfferDeeplink endpoint, which is now replaced by the getCredentialOffer endpoint (as
      it delivers the same information)
    - Added new endpoint patch `/management/api/credentials{credentialId}` which updates / creates the credential offer
      for a deferred endpoint.
    - Added a new ClientAgentInfoDto which are used for the deferred credential flow. This is stored in the database
      (db migration is necessary & included)
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
- Credential Offer is now validated according to the published metadata. Additional 'surprise' claims are no longer
  supported.
- Optional OAuth security with bearer tokens on `/management` endpoints.
  It can be activated and configured via spring environment variables.

### Fixed

- Fixed offers in status `DEFERRED` or `READY` expire when the `offer_expiration_timestamp` has passed.
- Checks for protected claims are now done in the create-offer-flow (1 step) instead of the issuance flow.
- Business Issuer is directly informed when the payload cannot be processed later.
- Fix status code when jwt filter criteria are not met from a 500 to 401.
- Fixed error code when deferred endpoint is called with invalid transaction id to INVALID_TRANSACTION_ID instead of
  INVALID_CREDENTIAL_REQUEST.

## Copied from Issuer Agent Management and Issuer Agent OID4VCI

Merge of issuer-agent-management 1.6.1 and issuer-agent-oid4vci into one service.

For migration merge environment variables. Please ensure that management endpoints are not accessible from public using
a WAF or Reverse-Proxy limiting the reachable endpoints.

Note: If using HSM for signing, both status list and credentials must be signed with HSM.