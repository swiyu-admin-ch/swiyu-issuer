# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.1

### Fixed

- Fix status code when jwt filter criteria are not met from a 500 to 401.

## 1.0.0
Merge of issuer-agent-management 1.6.1 and issuer-agent-oid4vci into one service.

For migration merge environment variables. Please ensure that management endpoints are not accessible from public using a WAF or Reverse-Proxy limiting the reachable endpoints.

Note: If using HSM for signing, both status list and credentials must be signed with HSM.