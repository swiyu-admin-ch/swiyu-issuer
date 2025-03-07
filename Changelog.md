# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.5

## Removed

- Deprecated Endpoints without version number are removed

## 1.2.4

### Changed

- Provide securosys HSM Primus jce provider

## 1.2.3

### Fixed

- Set connection timeout, read timeout and max redirects for rest client.

## 1.2.2

### Fixed

- Use separate pre-auth code instead of management id to get token

## 1.2.1

### Fixed

- Updated Spring Boot Parent, fixing CVE-2024-50379

## 1.2.0

### Added

- Extending prometheus export with metrics for build `runtime
- New optional credential_metadata field for providing metadata for vc creation, for example integrity hashes when adding { "vct#integrity": "<subresource integrity hash>" }

### Changed
- v1.1 ISO8601 compatibility for CredentialRequest
## 1.1.0

### Changed

- ISO8601 compatibility for CredentialRequest

### Fixed
- Status Lists are now sized correctly for the number of entries during creation, instead of reserving one full byte. This only affects status list creation. Existing status lists still work (though being larger than intended). 
- Fix a bug where the lock was not propagated correctly to the status list.

## 1.0.0

- Initial Release