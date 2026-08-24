# CredentialMedataSpez.md
**Static Compliance Check (AI Swagger Linting) - OID4VCI / Swiss Profile**

## 1. Endpoint: `GET /vct/{metadataKey}` (Credential Type Metadata)

This endpoint provides the SD-JWT VC Type Metadata. The OpenAPI specification (Swagger) must enforce the following structural and behavioral rules:

**HTTP Behavior & Content-Type**
* A successful response MUST return the payload using the `application/json` content type. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 4.2. JWT VC Issuer Metadata Response]
* Fetching Type Metadata via a Registry is NOT SUPPORTED within the Swiss Profile ecosystem. [Document: Swiss Profile for Verifiable Credentials, Chapter: 5.3.2. From a Registry]

**JSON Schema / Body Assertions**
* The Type Metadata document MUST be formatted as a JSON object. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]
* The `vct` property is REQUIRED and must be defined as a string. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]
* Extending (inheritance of) Type Metadata is NOT SUPPORTED; therefore, the `extends` property (and consequently `extends#integrity`) must not be expected or validated as mandatory in the schema. [Document: Swiss Profile for Verifiable Credentials, Chapter: 5.4. Extending Type Metadata]
* The property `name` is OPTIONAL and intended for a human-readable name. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]
* The property `description` is OPTIONAL and intended for a human-readable description. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]
* The property `display` is OPTIONAL and must be an array of objects containing display information for the credential type. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]
* The `display` property supports Overlay Capture Architecture (OCA) as a rendering method. If absent, clients will fall back to Issuer Metadata. [Document: Swiss Profile for Verifiable Credentials, Chapter: 7.1. Rendering Metadata]
* The property `claims` is OPTIONAL and must be an array of objects containing detailed information about the claims within the type. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.2. Type Metadata Format]

---

## 2. Endpoint: `GET /json-schema/{schemaKey}` (JSON Schema)

*(Important Validation Note: As per the SD-JWT VC draft 15 history, JSON Schema properties were explicitly removed from Type Metadata [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: Appendix D. Document History]. Therefore, the `schema_uri` property should not be strictly validated for modern implementations. If this endpoint remains in your Swagger file for legacy reasons or backward compatibility, enforce the following rules:)*

**HTTP Behavior & Application Logic**
* To guarantee privacy-preserving retrieval and prevent tracking (observability) by the issuer, Wallets SHOULD fetch and store Type Metadata documents in a local cache instead of requesting them dynamically. [Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache]
* Consequently, the API design must support local caching mechanisms. [Document: Swiss Profile for Verifiable Credentials, Chapter: Privacy-Preserving Retrieval of VCT Metadata]

---

## 3. Endpoint: `GET /oca/{ocaKey}` (Overlays Capture Architecture)

This endpoint delivers the OCA Bundle used for the graphical rendering and visualization of credentials.

**HTTP Behavior & Content-Type**
* The endpoint MUST associate the OCA Bundle with the `application/json` media type when it is retrieved via a URL. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC]
* The OCA Bundle SHOULD be represented as a single file containing a valid JSON object. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file]

**JSON Schema / Body Assertions (General Structure)**
* The JSON object MUST contain a `capture_bases` array containing one or more Capture Base objects. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file]
* Exactly ONE Root Capture Base must be defined within the bundle. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file]
* The JSON object MUST contain an `overlays` array containing zero, one, or more Overlay objects. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file]
* The OCA object "Capture Base 1.0" MUST be fully supported by the JSON schema. [Document: Swiss Profile for Verifiable Credentials, Chapter: Capture Base]

**Specific Overlay Assertions for Linting**
* The attributes `classification` and `flagged_attributes` within the Capture Base are NOT SUPPORTED and should be rejected or marked as unallowed by the schema rules. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Attributes]
* Code Tables within the "Entry & Entry Code Overlay 1.0" MUST NOT be supported. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Object Types]
* Implementations SHOULD utilize the Branding Overlay 1.1 and must explicitly set the "theme" attribute to "dark" to handle proper visualization when running in dark mode. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Aries Branding Overlay update]
* The "Data Source Mapping Overlay" must be supported in the schema to properly map Capture Base attributes to their corresponding data paths in the Verifiable Credential. [Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Data Source Mapping Overlay]