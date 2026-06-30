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

@DisplayName("Static Compliance Check: Swiss Profile Deferred Credential Endpoint")
class SwissProfileDeferredCredentialEndpointComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/api/deferred_credential";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/api/deferred_credential' must exist in the contract")
    void testDeferredCredentialEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: Deferred Credential endpoint MUST be accessible via POST")
    void testDeferredCredentialEndpointUsesPost() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        assertThat(pathItem.getPost())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The Deferred Credential endpoint MUST handle HTTP POST requests.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Response: HTTP 200 OK MUST be defined for successfully issued credentials")
    void testDeferredCredentialResponseIs200() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response200 = postOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A '200 OK' response MUST be defined for the Deferred Credential endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 200 response MUST use 'application/json' as the content type.")
                .containsKey("application/json");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Response: HTTP 202 Accepted MUST be defined for still-pending credential issuance")
    void testDeferredCredentialResponseIs202() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        assertThat(postOperation.getResponses().get("202"))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] If the credential issuance is still pending, the endpoint MUST return a '202 Accepted' response. This response MUST be defined in the contract.")
                .isNotNull();
    }

    @Test
    @DisplayName("Response: HTTP 400 Bad Request MUST be defined for invalid requests")
    void testDeferredCredential400BadRequestIsDefined() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        assertThat(postOperation.getResponses().get("400"))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] A '400 Bad Request' response MUST be defined for the Deferred Credential endpoint.")
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
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The request MUST require an 'Authorization' header containing a valid Access Token.")
                .isNotNull()
                .isNotEmpty();

        Parameter authHeader = parameters.stream()
                .filter(p -> "Authorization".equals(p.getName()) && "header".equals(p.getIn()))
                .findFirst()
                .orElse(null);
        assertThat(authHeader)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] An 'Authorization' header parameter MUST be defined.")
                .isNotNull();
        assertThat(authHeader.getRequired())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The 'Authorization' header MUST be marked as required.")
                .isTrue();
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Security: 'DPoP' header MUST be defined and required for DPoP key binding")
    void testDPoPHeaderIsRequired() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        List<Parameter> parameters = postOperation.getParameters();
        assertThat(parameters)
                .as("[Document: Swiss Profile Issuance, Chapter: 10] Parameters must be defined on the Deferred Credential endpoint.")
                .isNotNull();

        Parameter dpopHeader = parameters.stream()
                .filter(p -> "DPoP".equals(p.getName()) && "header".equals(p.getIn()))
                .findFirst()
                .orElse(null);
        assertThat(dpopHeader)
                .as("[Document: Swiss Profile Issuance, Chapter: 10] A 'DPoP' header parameter MUST be defined.")
                .isNotNull();
        assertThat(dpopHeader.getRequired())
                .as("[Document: Swiss Profile Issuance, Chapter: 10] The Access Token MUST be bound to the Holder's DPoP key, hence the 'DPoP' header MUST be marked as required.")
                .isTrue();
    }

    // --- Tier 4: JSON Schema Assertions — Request Body ---

    @Test
    @DisplayName("Request Schema: 'transaction_id' MUST be a required string property")
    void testTransactionIdIsRequiredAndString() {
        Schema<?> schema = getRequestBodySchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] A schema must be defined for the 'application/json' request body.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The 'transaction_id' property MUST be declared as required.")
                .isNotNull()
                .contains("transaction_id");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] Schema properties must be defined and include 'transaction_id'.")
                .isNotNull()
                .containsKey("transaction_id");
        assertThat(properties.get("transaction_id").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.1] The 'transaction_id' property MUST be defined as a string.")
                .isNotNull()
                .contains("string");
    }

    // --- Tier 4: JSON Schema Assertions — Response Body (200 OK) ---

    @Test
    @DisplayName("Response Schema (200): MUST define either 'credential' at top level or 'credentials' as an array")
    void testCredentialOrCredentialsExistsInResponse() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A schema must be defined for the 200 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The response schema MUST define either a 'credential' property (top-level singular) or a 'credentials' property (array) to carry the issued credential(s).")
                .isNotNull()
                .matches(p -> p.containsKey("credential") || p.containsKey("credentials"),
                        "must contain either 'credential' or 'credentials'");
    }

    @Test
    @DisplayName("Response Schema (200): 'c_nonce' MUST be a string and MUST NOT be required if present")
    void testCNonceIsOptionalString() {
        Schema<?> schema = getResponseSchema("200");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A schema must be defined for the 200 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("c_nonce")) {
            assertThat(properties.get("c_nonce").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] If 'c_nonce' is defined, it MUST be of type 'string'.")
                    .isNotNull()
                    .contains("string");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 'c_nonce' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("c_nonce");
        }
    }

    // --- Tier 4: JSON Schema Assertions — Response Body (202 Accepted) ---

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Response Schema (202): 'transaction_id' MUST be a required string property")
    void testTransactionIdIsRequiredIn202() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response202 = postOperation.getResponses().get("202");
        assertThat(response202)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A '202 Accepted' response MUST be defined.")
                .isNotNull();

        Schema<?> schema = getResponseSchema("202");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A schema must be defined for the 202 response.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 'transaction_id' parameter MUST be required in the 202 response to identify the ongoing transaction.")
                .isNotNull()
                .contains("transaction_id");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Response Schema (202): 'interval' MUST be a required integer property")
    void testIntervalIsRequiredIn202() {
        Schema<?> schema = getResponseSchema("202");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A schema must be defined for the 202 response.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 'interval' parameter MUST be required in the 202 response, representing the minimum wait time in seconds before the Wallet polls again.")
                .isNotNull()
                .contains("interval");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] Schema properties must be defined and include 'interval'.")
                .isNotNull()
                .containsKey("interval");
        assertThat(properties.get("interval").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 'interval' property MUST be defined as an integer.")
                .isNotNull()
                .contains("integer");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Response Schema (202): MUST NOT contain a 'credential' property")
    void testCredentialNotPresentIn202() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response202 = postOperation.getResponses().get("202");
        assertThat(response202)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A '202 Accepted' response MUST be defined.")
                .isNotNull();

        Schema<?> schema = getResponseSchema("202");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] A schema must be defined for the 202 response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            assertThat(properties)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.2] The 202 response MUST NOT contain a 'credential' or 'credentials' property — only 'transaction_id' and 'interval' are valid.")
                    .doesNotContainKey("credential")
                    .doesNotContainKey("credentials");
        }
    }

    // --- Tier 4: JSON Schema Assertions — Response Body (400 Bad Request) ---

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Response Schema (400): MUST be a JSON object with an 'error' required string property")
    void test400ErrorPropertyIsRequiredString() {
        Operation postOperation = getPostOperation();
        assertThat(postOperation).isNotNull();

        ApiResponse response400 = postOperation.getResponses().get("400");
        assertThat(response400)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] A '400 Bad Request' response MUST be defined.")
                .isNotNull();
        assertThat(response400.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 400 response MUST define content.")
                .isNotNull();
        assertThat(response400.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 400 response MUST use 'application/json' as the content type.")
                .containsKey("application/json");

        Schema<?> schema = getResponseSchema("400");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] A schema must be defined for the 400 'application/json' error response.")
                .isNotNull();

        assertThat(schema.getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 400 error response MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 'error' property MUST be declared as required in the error response.")
                .isNotNull()
                .contains("error");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The error response schema MUST define properties including 'error'.")
                .isNotNull()
                .containsKey("error");
        assertThat(properties.get("error").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 'error' property MUST be defined as a string type.")
                .isNotNull()
                .contains("string");
    }

    @Test
    @DisplayName("Response Schema (400): 'error_description' MUST be an optional string property if present")
    void test400ErrorDescriptionIsOptionalString() {
        Schema<?> schema = getResponseSchema("400");
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] A schema must be defined for the 400 error response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("error_description")) {
            assertThat(properties.get("error_description").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] If 'error_description' is defined, it MUST be of type 'string'.")
                    .isNotNull()
                    .contains("string");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 9.3] The 'error_description' property is OPTIONAL and MUST NOT be declared as required.")
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


}
