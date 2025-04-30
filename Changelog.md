# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.0

### Added

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
    - Fixed incorrect error code when access token is wrong to INVALID_TOKEN instead of INVALID_CREDENTIAL.

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

## 1.1.6

### Added

- Added audit metadata to entities

## 1.1.5

### Changed

- Changed workflow file to fix image build on github

## 1.1.4

### Changed

- Accept more varied empty proofs (now also accepts an empty map)

## 1.1.3

### Changed

- Disabled logging of all actuator requests. The default filter regex pattern is `.*/actuator/.*`. The expression can be
  customized by setting the `request.logging.uri-filter-pattern` property.

## 1.1.2

### Added

- sd-jwt holder binding proof in jwt format can now not be issued too long ago or too far in the future.

### Changed

- Provide securosys HSM Primus jce provider (no change necessary for user)

## 1.1.1

### Fixed

- Use separate pre-auth code instead of management id to get token

## 1.1.0

### Added

- Add new credential_metadata field to database, allowing for arbitrary vc metadata to be passed along. Using the first
  defined field - vct#integrity
-
- Extending prometheus export with metrics for build

### Changed

- Restrict issuer_metadata cryptographic_binding_methods_supported property to a predefined set of values. For the time
  being it is always did:jwk. Allowed
  values are defined in the [README under allowed config values](README.md#allowed-config-values)

### Fixed

- Updated Spring Boot Parent, fixing CVE-2024-50379

## 1.0.1

- Add optional endpoints to deliver vct, json-schema and oca.

## 1.0.0

- Initial Release