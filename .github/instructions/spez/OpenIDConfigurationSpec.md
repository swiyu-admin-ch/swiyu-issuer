# OpenIDConfigurationSpec.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## Endpoint: `GET /.well-known/openid-configuration`

This endpoint serves as the Discovery endpoint (OpenID Provider Configuration / OAuth 2.0 Authorization Server Metadata). It provides the Wallet with essential metadata about how to authenticate with the Credential Issuer, where the token endpoints are located, and which cryptographic methods (e.g., for DPoP) are supported.

**HTTP Behavior & Content-Type**
* The endpoint MUST process HTTP `GET` requests, as Discovery metadata is standardized to be retrieved via GET (a POST is functionally invalid). [Document: OpenID Connect Discovery 1.0, Chapter: 4.1]
* The endpoint MUST return the HTTP status code `200 (OK)` when the metadata is successfully retrieved. [Document: OpenID Connect Discovery 1.0, Chapter: 4.1]
* The API MUST return the response with the media type `application/json`. [Document: OpenID Connect Discovery 1.0, Chapter: 4.1]

**Security & Headers**
* The endpoint MUST be publicly accessible and MUST NOT require authentication (such as an Access Token in the Authorization header). [Document: OpenID Connect Discovery 1.0, Chapter: 4.1]
* Communication MUST strictly occur over TLS (HTTPS). [Document: OpenID Connect Discovery 1.0, Chapter: 4.1]

**JSON Schema / Request Body Assertions**
* Since this is an HTTP `GET` endpoint, the schema MUST NOT require or define a request body (`requestBody`). [Document: RFC 7231, Chapter: 4.3.1]

**JSON Schema / Response Body Assertions**
* The JSON schema of the response MUST define the `issuer` property as REQUIRED, and the type MUST be a string (HTTPS URL). [Document: OpenID Connect Discovery 1.0, Chapter: 3]
* The response schema MUST define the properties `authorization_endpoint`, `token_endpoint`, and `jwks_uri` as REQUIRED (type String/URL). [Document: OpenID Connect Discovery 1.0, Chapter: 3]
* The properties `response_types_supported`, `subject_types_supported`, and `id_token_signing_alg_values_supported` are OIDC-specific fields required by OpenID Connect Discovery 1.0. In a pure OID4VCI Credential Issuer context (no ID Token issuance), these fields are NOT mandatory: OID4VCI (Chapter 11) permits using RFC 8414 Authorization Server Metadata, which does not prescribe these fields. If present in the schema, each MUST be an array of strings and MUST NOT be declared as required. [Document: OID4VCI, Chapter: 11; OpenID Connect Discovery 1.0, Chapter: 3]
* The `grant_types_supported` property is OPTIONAL in the response schema. If absent, the default value `["authorization_code", "implicit"]` MUST be assumed. If present, it MUST be an array of strings and MUST NOT be declared as required. [Document: RFC 8414 - OAuth 2.0 Authorization Server Metadata, Section: 2]
* The `dpop_signing_alg_values_supported` property is OPTIONAL in the response schema. If present, it MUST be an array of strings and MUST NOT be declared as required. If absent, the supported JWS algorithms MUST be assumed to be the ones listed in the Swiss Profile under Cryptography. [Document: Swiss Profile Issuance, Appendix D]
* The response schema SHOULD explicitly ensure that the `registration_endpoint` property is NOT present (or Client Registration is marked as NOT SUPPORTED), since dynamic client registration is explicitly excluded in the Swiss Profile. [Document: Swiss Profile Issuance, Chapter: 5.2]