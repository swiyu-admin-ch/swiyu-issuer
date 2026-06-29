# DeferredCredentialEndpointSpez.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## Endpoint: `POST /deferred_credential`

This endpoint is used by the Wallet to retrieve one or multiple Verifiable Credentials that could not be issued immediately at the Credential Endpoint (asynchronous issuance). The Wallet uses a transaction identifier provided during the initial request to fetch the pending credential(s). The specification enforces strict transaction tracking, DPoP binding, and mandatory Swiss Profile encryption overrides.

**HTTP Behavior & Content-Type**
* The endpoint MUST handle HTTP `POST` requests. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1]
* A successful response where the credential is ready MUST return the HTTP `200 (OK)` status code. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]
* If the credential issuance is still pending, the endpoint MUST return an HTTP `202 (Accepted)` status code. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]
* The API MUST require the Deferred Credential Request to be encrypted (`credential_request_encryption` MUST be strictly required with `encryption_required` set to `true`). [Document: Swiss Profile Issuance, Chapter: 12.2.4]
* The API MUST return an encrypted Deferred Credential Response (`credential_response_encryption` MUST be strictly required with `encryption_required` set to `true`). [Document: Swiss Profile Issuance, Chapter: 12.2.4]

**Security & Headers**
* The request MUST require an `Authorization` header containing a valid OAuth 2.0 Access Token. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1]
* The Access Token MUST be cryptographically bound to the Holder's DPoP key, hence DPoP HTTP headers MUST be enforced. [Document: Swiss Profile Issuance, Chapter: 10]

**JSON Schema / Request Body Assertions**
* The `transaction_id` property MUST be REQUIRED to identify the pending issuance transaction. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1]
* The `transaction_id` property MUST be defined as a string type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1]

**JSON Schema / Response Body Assertions (HTTP 200 OK)**
* The response schema MUST define either a `credential` property at the top level (singular, immediate issuance) OR a `credentials` property as an array (batch issuance). At least one of these MUST be present. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]
* The `c_nonce` property is OPTIONAL and MUST be defined as a string if present. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]

**JSON Schema / Response Body Assertions (HTTP 202 Accepted)**
* The response schema MUST require the `transaction_id` parameter to identify the ongoing transaction. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]
* The response schema MUST require the `interval` parameter, defined as a number representing the minimum wait time in seconds before the Wallet should poll again. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]
* The `credential` property MUST NOT be present in the 202 response — only `transaction_id` and `interval` are valid. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2]

**JSON Schema / Response Body Assertions (HTTP 400 Bad Request)**
* For error responses, the schema MUST require an `error` property. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3]
* The `error` property MUST be defined as a string type (e.g., expecting values like `invalid_transaction_id`). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3]
* The `error_description` property is OPTIONAL and MUST be defined as a string type if present. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3]