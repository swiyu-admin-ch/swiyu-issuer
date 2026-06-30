# CredentialIssuerMetadataSpec.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## Endpoint: `GET /.well-known/openid-credential-issuer`

This endpoint provides the Credential Issuer Metadata. It serves as the primary discovery endpoint through which Wallets learn which credential types the issuer offers, where the associated API endpoints (Credential Endpoint, Deferred Endpoint) are located, and – centrally for the Swiss Profile – which Trust Statements prove the issuer's legitimacy.

**HTTP Behavior & Content-Type**
* The endpoint MUST handle HTTP `GET` requests. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2]
* Upon successful retrieval, the HTTP status code `200 (OK)` MUST be returned. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2]
* The API MUST deliver the response using the `application/json` media type. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2]

**Security & Headers**
* The endpoint MUST be publicly accessible and MUST NOT require any authentication (such as an Access Token). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2]
* Communication MUST strictly occur over TLS (HTTPS). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2]

**JSON Schema / Request Body Assertions**
* Since this is an HTTP `GET` endpoint, the schema MUST NOT require or define a Request Body (`requestBody`). [Document: RFC 7231, Chapter: 4.3.1]

**JSON Schema / Response Body Assertions**
* The response schema MUST define the `credential_issuer` property as REQUIRED, and the type MUST be a string (HTTPS URL). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3]
* The response schema MUST define the `credential_endpoint` property as REQUIRED (Type String/URL). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3]
* The response schema MUST define the `credential_configurations_supported` property as REQUIRED. The type MUST be a JSON object that acts as a map. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3]
* According to the Trust Protocol, the schema MUST define the `credential_issuer_identity_trust_statement` property at the top level as REQUIRED (Type String/JWT) to prove the issuer's identity. [Document: Swiss Profile Trust, Chapter: Trust Markers]
* Within the credential definitions in `credential_configurations_supported`, the `protected_issuance_authorization_trust_statement` property MUST NOT be required for each protected VC format. [Document: Swiss Profile Trust, Chapter: Trust Markers]
* Within each credential configuration in `credential_configurations_supported`, the `format` property MUST be declared as REQUIRED. [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3]
* If asynchronous issuance (Deferred Issuance) is supported, the `deferred_credential_endpoint` property MUST be defined at the top level (Type String/URL). [Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3]
* (For SD-JWT formats) Within the credential configuration in `credential_configurations_supported`, the `vct` property SHOULD be strictly required, as the Swiss Profile relies on SD-JWT VC or dc+sd-jwt. [Document: SD-JWT-based Verifiable Digital Credentials (SD-JWT VC), Chapter: 4.2 Type Metadata Format]