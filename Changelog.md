# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.3.3

### Changed

- Changed workflow file to fix image build on github

## 1.3.2

### Changed

- Disabled logging of all actuator requests. The default filter regex pattern is `.*/actuator/.*`. The expression can be
  customized by setting the `request.logging.uri-filter-pattern` property.

## 1.3.1

### Added

- Added interceptor for evaluating status list size

## 1.3.0

### Changed

- Change deeplink schema to swiyu. It can be changed with an environment variable if need be, but no action on issuer
  side should be necessary. A new wallet version is needed

## 1.2.7

### Fixed

- Fixed potential decompression bomb security issue

## 1.2.6

### Fixed

- improved error message on missing auth token for accessing status registry
- updated issuer_metadata in sample.compose.yml to be valid

## 1.2.5

### Changed

- internal technical cleanups

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
- New optional credential_metadata field for providing metadata for vc creation, for example integrity hashes when
  adding { "vct#integrity": "<subresource integrity hash>" }

### Changed

- v1.1 ISO8601 compatibility for CredentialRequest

## 1.1.0

### Changed

- ISO8601 compatibility for CredentialRequest

### Fixed

- Status Lists are now sized correctly for the number of entries during creation, instead of reserving one full byte.
  This only affects status list creation. Existing status lists still work (though being larger than intended).
- Fix a bug where the lock was not propagated correctly to the status list.

## 1.0.0

- Initial Release