# NonceEndpointSpez.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## Endpoint: `POST /nonce` (Nonce Endpoint)

This endpoint provides a fresh credential nonce (`c_nonce`) to the Wallet, which is required to prove possession of the key bound to the credential during the Credential Request. Additionally, because the Swiss Profile utilizes DPoP, this endpoint must enforce DPoP HTTP headers.

The OpenAPI specification (Swagger) must enforce the following structural and behavioral rules:

**HTTP Behavior & Content-Type**
* The endpoint MUST handle HTTP POST requests. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request]
* A successful response MUST return the HTTP 200 (OK) status code. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]
* A successful response MUST return the payload using the `application/json` content type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]

**Security & DPoP Header Assertions (RFC 9449)**
* The Nonce Endpoint is **NOT a protected resource** — the Wallet does not need to supply an access token. Therefore, no `Authorization` header and no `DPoP` request header are required or expected. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request]
* The successful response MAY include a `DPoP-Nonce` HTTP header to supply the client with a fresh DPoP nonce. Since this is a MAY, it is not a compliance failure if the header is absent from the contract. [Document: RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP), Chapter: 8.1. Nonce Syntax]

**JSON Schema / Response Body Assertions**
* The Nonce Response document MUST be formatted as a JSON object. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]
* The `c_nonce` property is REQUIRED. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]
* The `c_nonce` property MUST be defined as a string. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]
* There is NO `c_nonce_expires_in` property in the Nonce Response — it was present in older drafts but removed from OID4VCI 1.0 final. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response]