# CredentialEndpointSpez.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## Endpoint: `POST /credential` (Credential Endpoint)

This endpoint represents the Credential Endpoint where the Wallet requests the issuance of one or multiple Verifiable Credentials from the Credential Issuer. The specification enforces mandatory encryption parameters, DPoP bindings, and specific JSON Schema constraints as mandated by the OID4VCI specification and the Swiss Profile overrides.

**HTTP Behavior & Content-Type**
* The endpoint MUST handle HTTP POST requests for credential issuance. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint]
* A successful response MUST return the HTTP 200 (OK) status code. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* The endpoint MUST accept requests with the `application/json` content type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* A successful response MUST return the payload using the `application/json` content type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* If a request is malformed or requests an unsupported credential, the endpoint MUST return an HTTP status code 400 (Bad Request). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response]

**Security & Headers**
* The request MUST require an `Authorization` header containing a valid Access Token. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint]
* The Access Token MUST be bound to the Holder's DPoP key, hence DPoP headers MUST be enforced. [Document: Swiss Profile Issuance, Chapter: 10. Authorization Code Binding to a DPoP Key]

**JSON Schema / Request Body Assertions**
* The Credential Request document MUST be formatted as a JSON object. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* The `credential_configuration_id` property (String) MUST be expected by the schema to identify the requested credential type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* Because the Swiss Profile strictly requires response encryption, the `credential_response_encryption` object SHOULD be enforced as a required element in the request payload. [Document: Swiss Profile Issuance, Chapter: 12.2.4]
* Inside the `credential_response_encryption` object, the `jwk` property (containing the public key as JWK) MUST be required. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* Inside the `credential_response_encryption` object, the `enc` property (JWE content-encryption algorithm) MUST be required. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* Inside the `credential_response_encryption` object, the `zip` property (JWE compression algorithm) is OPTIONAL. There is NO `alg` property — `alg` belongs to the Signed Metadata JOSE header (Section 12.2.3), not to credential response encryption. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* The schema MUST support the `proofs` property to allow batch credential issuance. [Document: Swiss Profile Issuance, Chapter: 12.2.4]
* The schema MUST allow the `proofs` array to accept a minimum size of 10 items. [Document: Swiss Profile Issuance, Chapter: 12.2.4]
* The `proofs` object uses the proof type name as the **key** (e.g., `"jwt"`, `"di_vp"`), and the value is a non-empty array of proof strings. There is NO `proof_type` property — the key itself identifies the proof type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]
* The `proofs.jwt` property MUST be defined as an array of strings, each carrying one JWT proof. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request]

**JSON Schema / Response Body Assertions (HTTP 200 OK)**
* The Credential Response document MUST be formatted as a JSON object. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* The `credential` property MUST be supported and defined (typically as a String for SD-JWT VC format) for immediate issuance. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* The `transaction_id` property (String) MAY be supported for Deferred Credential Issuance flows. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* The `c_nonce` property is OPTIONAL and MUST be defined as a string if present. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]
* The `c_nonce_expires_in` property is OPTIONAL and MUST be defined as an integer representing seconds. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response]

**JSON Schema / Response Body Assertions (HTTP 400 Bad Request)**
* For error responses, the schema MUST require an `error` property. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response]
* The `error` property MUST be defined as a string type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response]
* The `error_description` property is OPTIONAL and MUST be defined as a string if present. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response]