# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- v1.1 ISO8601 compatibility for CredentialRequest

### Fixed
- Status Lists are now sized correctly for the number of entries during creation, instead of reserving one full byte. This only affects status list creation. Existing status lists still work (though being larger than intended). 
- Fix a bug where the lock was not propagated correctly to the status list.

## 1.0.0

- Initial Release