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
* The response schema MUST define the properties `response_types_supported`, `subject_types_supported`, and `id_token_signing_alg_values_supported` as REQUIRED (each as an array of strings). [Document: OpenID Connect Discovery 1.0, Chapter: 3]
* The response schema MUST define the `grant_types_supported` property as an array of strings, which MUST include the value `authorization_code` (and `urn:ietf:params:oauth:grant-type:pre-authorized_code` if Pre-Authorized Code Flows are supported). [Document: RFC 8414 - OAuth 2.0 Authorization Server Metadata, Chapter: 2]
* Because the Swiss Profile strictly requires DPoP, the response schema MUST define the `dpop_signing_alg_values_supported` property as an array of strings to declare the permitted signature algorithms. [Document: Swiss Profile Issuance, Chapter: 10]
* The response schema SHOULD explicitly ensure that the `registration_endpoint` property is NOT present (or Client Registration is marked as NOT SUPPORTED), since dynamic client registration is explicitly excluded in the Swiss Profile. [Document: Swiss Profile Issuance, Chapter: 5.2]