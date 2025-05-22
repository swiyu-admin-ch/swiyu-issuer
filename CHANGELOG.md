# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.0

### Added

- Added new endpoint `/.well-known/oauth-authorization-server` that provides the same information as the
  `/.well-known/openid-configuration` endpoint but in a OAuth2-centric way.
- The `/.well-known/openid-configuration` still exists and is not deprecated.

## 1.1.1

### Fixed

- rename issuer-agent to swiyu-issuer-service in documentation and configuration

## 1.1.0

### Added
- Enable requesting Key Attestation via Issuer Metadata
- Enable receiving and verification of Key Attestations in Credential Request Proofs.

### Fixed

- Checks for protected claims are now done in the create-offer-flow (1 step) instead of the issuance flow.
- Business Issuer is directly informed when the payload cannot be processed later.

## 1.0.1

### Fixed

- Fix status code when jwt filter criteria are not met from a 500 to 401.

## 1.0.0
Merge of issuer-agent-management 1.6.1 and issuer-agent-oid4vci into one service.

For migration merge environment variables. Please ensure that management endpoints are not accessible from public using a WAF or Reverse-Proxy limiting the reachable endpoints.

Note: If using HSM for signing, both status list and credentials must be signed with HSM.
