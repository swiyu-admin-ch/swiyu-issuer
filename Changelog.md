# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.2.0
### Added
- Extending prometheus export with metrics for build `runtime
- New optional credential_metadata field for providing metadata for vc creation, for example integrity hashes when adding { "vct#integrity": "<subresource integrity hash>" }

### Changed
- v1.1 ISO8601 compatibility for CredentialRequest
## 1.1.0
### Changed
- ISO8601 compatibility for CredentialRequest

## 1.0.0

- Initial Release