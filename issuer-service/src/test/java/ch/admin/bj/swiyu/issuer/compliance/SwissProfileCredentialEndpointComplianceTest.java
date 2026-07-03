package ch.admin.bj.swiyu.issuer.compliance;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Static Compliance Check: Swiss Profile Credential Endpoint")
class SwissProfileCredentialEndpointComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/api/credential";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/api/credential' must exist in the contract")
    void testCredentialEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: Credential endpoint MUST be accessible via POST")
    void testCredentialEndpointUsesPost() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        assertThat(pathItem.getPost())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] The Credential endpoint MUST handle HTTP POST requests.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Response: Successful response MUST return HTTP 200 OK with 'application/json'")
    void testCredentialResponseIs200WithApplicationJson() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response200 = postOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A '200 OK' response MUST be defined for the Credential endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A successful response MUST use 'application/json' as the content type.")
                .containsKey("application/json");
    }

    @Test
    @DisplayName("Request: Endpoint MUST accept 'application/json' in the request body")
    void testCredentialRequestAcceptsApplicationJson() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        assertThat(postOperation.getRequestBody())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] A request body MUST be defined for the Credential endpoint.")
                .isNotNull();
        assertThat(postOperation.getRequestBody().getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The request body MUST define content.")
                .isNotNull();
        assertThat(postOperation.getRequestBody().getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The endpoint MUST accept requests with the 'application/json' content type.")
                .containsKey("application/json");
    }

    @Test
    @DisplayName("Response: HTTP 400 Bad Request MUST be defined for malformed or unsupported requests")
    void testCredential400BadRequestIsDefined() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        assertThat(postOperation.getResponses().get("400"))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] If a request is malformed or requests an unsupported credential, the endpoint MUST return an HTTP 400 Bad Request response. This response MUST be defined in the contract.")
                .isNotNull();
    }

    // --- Security & Headers ---

    @Test
    @DisplayName("Security: 'Authorization' header MUST be defined and required")
    void testAuthorizationHeaderIsRequired() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        List<Parameter> parameters = postOperation.getParameters();
        assertThat(parameters)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] The request MUST require an 'Authorization' header containing a valid Access Token.")
                .isNotNull()
                .isNotEmpty();

        Parameter authHeader = parameters.stream()
                .filter(p -> "Authorization".equals(p.getName()) && "header".equals(p.getIn()))
                .findFirst()
                .orElse(null);
        assertThat(authHeader)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] An 'Authorization' header parameter MUST be defined.")
                .isNotNull();
        assertThat(authHeader.getRequired())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8. Credential Endpoint] The 'Authorization' header MUST be marked as required.")
                .isTrue();
    }


    // --- Tier 4: JSON Schema Assertions — Request Body ---

    @Test
    @DisplayName("Request Schema: Request body MUST be a JSON object")
    void testCredentialRequestBodyIsObject() {
        Schema<?> schema = getRequestBodySchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] A schema must be defined for the 'application/json' request body.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The Credential Request document MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Test
    @DisplayName("Request Schema: 'credential_configuration_id' MUST be a required string property")
    void testCredentialConfigurationIdIsRequiredAndString() {
        Schema<?> schema = getRequestBodySchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] A schema must be defined for the request body.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The 'credential_configuration_id' property MUST be declared as required.")
                .isNotNull()
                .contains("credential_configuration_id");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] Schema properties must be defined and include 'credential_configuration_id'.")
                .isNotNull()
                .containsKey("credential_configuration_id");
        assertThat(properties.get("credential_configuration_id").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The 'credential_configuration_id' property MUST be defined as a string.")
                .isNotNull()
                .contains("string");
    }
    @Test
    @DisplayName("Request Schema: 'credential_response_encryption' MUST be required (Swiss Profile mandates encryption)")
    void testCredentialResponseEncryptionIsRequired() {
        Schema<?> schema = getRequestBodySchema();
        assertThat(schema)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] A schema must be defined for the request body.")
                .isNotNull();
    }

    @Test
    @DisplayName("Request Schema: 'credential_response_encryption.jwk' MUST be required")
    void testCredentialResponseEncryptionJwkIsRequired() {
        Schema<?> encryptionSchema = getCredentialResponseEncryptionSchema();
        assertThat(encryptionSchema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The 'credential_response_encryption' schema must be defined.")
                .isNotNull();

        List<String> required = encryptionSchema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] Inside 'credential_response_encryption', the 'jwk' property (containing the public key) MUST be required.")
                .isNotNull()
                .contains("jwk");
    }

    @Test
    @DisplayName("Request Schema: 'credential_response_encryption.enc' MUST be a required string property")
    void testCredentialResponseEncryptionEncIsRequired() {
        Schema<?> encryptionSchema = getCredentialResponseEncryptionSchema();
        assertThat(encryptionSchema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] The 'credential_response_encryption' schema must be defined.")
                .isNotNull();

        List<String> required = encryptionSchema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.2. Credential Request] Inside 'credential_response_encryption', the 'enc' property (JWE content-encryption algorithm) MUST be required.")
                .isNotNull()
                .contains("enc");
    }

    @Test
    @DisplayName("Request Schema: 'proofs' property MUST exist to support batch credential issuance")
    void testProofsPropertyExists() {
        Schema<?> schema = getRequestBodySchema();
        assertThat(schema)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] A schema must be defined for the request body.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] The schema MUST support the 'proofs' property to allow batch credential issuance.")
                .isNotNull()
                .containsKey("proofs");
    }

    @Test
    @DisplayName("Request Schema: 'proofs.jwt' array MUST allow a minimum of 10 items")
    void testProofsJwtMinItems() {
        Schema<?> proofsSchema = getProofsDtoSchema();
        assertThat(proofsSchema)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] The 'proofs' schema must be defined.")
                .isNotNull();

        Map<String, Schema> properties = proofsSchema.getProperties();
        assertThat(properties)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] The 'proofs' schema must define properties.")
                .isNotNull()
                .containsKey("jwt");

        Schema<?> jwtArraySchema = properties.get("jwt");
        Integer minItems = jwtArraySchema.getMinItems();
        assertThat(minItems)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] The schema MUST allow the 'proofs' array to accept a minimum size of 10 items. Current minItems is too restrictive.")
                .isNotNull();
        assertThat(minItems)
                .as("[Document: Swiss Profile Issuance, Chapter: 12.2.4] The 'proofs.jwt' array minItems MUST be at least 10 to support batch credential issuance.")
                .isGreaterThanOrEqualTo(10);
    }

    // --- Tier 4: JSON Schema Assertions — Response Body (200 OK) ---

    @Test
    @DisplayName("Response Schema (200): Response body MUST be a JSON object")
    void testCredentialResponseBodyIsObject() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A schema must be defined for the 200 'application/json' response.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The Credential Response document MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Test
    @DisplayName("Response Schema (200): 'credentials' MUST be an optional array property")
    void testCredentialsArrayInResponse() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A schema must be defined for the 200 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credentials' array property MUST be defined in the response schema.")
                .isNotNull()
                .containsKey("credentials");
        assertThat(properties.get("credentials").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credentials' property MUST be of type 'array'.")
                .isNotNull()
                .contains("array");

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credentials' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("credentials");
        }
    }

    @Test
    @DisplayName("Response Schema (200): Each element of 'credentials' MUST contain a 'credential' string property")
    void testCredentialPropertyInsideCredentialsArray() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties).isNotNull();

        Schema<?> credentialsArray = (Schema<?>) properties.get("credentials");
        assertThat(credentialsArray)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credentials' array must be defined.")
                .isNotNull();

        Schema<?> itemSchema = credentialsArray.getItems();
        assertThat(itemSchema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credentials' array MUST define an items schema.")
                .isNotNull();

        Map<String, Schema> itemProperties = itemSchema.getProperties();
        assertThat(itemProperties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] Each element of 'credentials' MUST contain a 'credential' property.")
                .isNotNull()
                .containsKey("credential");
        assertThat(itemProperties.get("credential").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'credential' property MUST be defined as a string (SD-JWT VC format).")
                .isNotNull()
                .contains("string");
    }

    @Test
    @DisplayName("Response Schema (200): 'c_nonce' MUST be a string and MUST NOT be required if present")
    void testCNonceIsOptionalString() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A schema must be defined for the 200 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("c_nonce")) {
            assertThat(properties.get("c_nonce").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] If 'c_nonce' is defined, it MUST be of type 'string'.")
                    .isNotNull()
                    .contains("string");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'c_nonce' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("c_nonce");
        }
    }

    @Test
    @DisplayName("Response Schema (200): 'c_nonce_expires_in' MUST be an integer and MUST NOT be required if present")
    void testCNonceExpiresInIsOptionalInteger() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] A schema must be defined for the 200 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("c_nonce_expires_in")) {
            assertThat(properties.get("c_nonce_expires_in").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] If 'c_nonce_expires_in' is defined, it MUST be of type 'integer' representing seconds.")
                    .isNotNull()
                    .contains("integer");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3. Credential Response] The 'c_nonce_expires_in' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("c_nonce_expires_in");
        }
    }

    // --- Tier 4: JSON Schema Assertions — Response Body (400 Bad Request) ---

    @Test
    @DisplayName("Response Schema (400): 'error' MUST be a required string property")
    void test400ErrorPropertyIsRequiredString() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response400 = postOperation.getResponses().get("400");
        assertThat(response400)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] A '400 Bad Request' response MUST be defined.")
                .isNotNull();

        assertThat(response400.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 400 response MUST define content.")
                .isNotNull();
        assertThat(response400.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 400 response MUST use 'application/json' as the content type.")
                .containsKey("application/json");

        Schema<?> schema = getResponseSchema("400");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] A schema must be defined for the 400 'application/json' error response.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 'error' property MUST be required in the error response.")
                .isNotNull()
                .contains("error");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The error response schema MUST define properties including 'error'.")
                .isNotNull()
                .containsKey("error");
        assertThat(properties.get("error").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 'error' property MUST be defined as a string type.")
                .isNotNull()
                .contains("string");
    }

    @Test
    @DisplayName("Response Schema (400): 'error_description' MUST be an optional string property if present")
    void test400ErrorDescriptionIsOptionalString() {
        Schema<?> schema = getResponseSchema("400");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] A schema must be defined for the 400 error response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The error response schema MUST define an 'error_description' property.")
                .isNotNull()
                .containsKey("error_description");

        assertThat(properties.get("error_description").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 'error_description' property is OPTIONAL and MUST be defined as a string if present.")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 8.3.1.2. Credential Error Response] The 'error_description' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("error_description");
        }
    }

    // --- Helper Methods ---

    private static Operation getPostOperation() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        if (pathItem == null) return null;
        return pathItem.getPost();
    }

    private static Schema<?> getRequestBodySchema() {
        Operation postOperation = getPostOperation();
        if (postOperation == null || postOperation.getRequestBody() == null) return null;
        var content = postOperation.getRequestBody().getContent();
        if (content == null) return null;
        var mediaType = content.get("application/json");
        if (mediaType == null) return null;
        return mediaType.getSchema();
    }

    private static Schema<?> getResponseSchema(String statusCode) {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        return getResponseSchema(pathItem, statusCode);
    }


    private static Schema<?> getCredentialResponseEncryptionSchema() {
        Schema<?> requestSchema = getRequestBodySchema();
        if (requestSchema == null || requestSchema.getProperties() == null) return null;
        return (Schema<?>) requestSchema.getProperties().get("credential_response_encryption");
    }

    private static Schema<?> getProofsDtoSchema() {
        Schema<?> requestSchema = getRequestBodySchema();
        if (requestSchema == null || requestSchema.getProperties() == null) return null;
        return (Schema<?>) requestSchema.getProperties().get("proofs");
    }
}
