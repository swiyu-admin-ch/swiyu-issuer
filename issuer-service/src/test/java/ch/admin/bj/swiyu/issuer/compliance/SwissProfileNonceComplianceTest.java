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

@DisplayName("Static Compliance Check: Swiss Profile Nonce Endpoint")
class SwissProfileNonceComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/api/nonce";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/api/nonce' must exist in the contract")
    void testNonceEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: Nonce endpoint MUST be accessible via POST")
    void testNonceEndpointUsesPost() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation postOperation = pathItem.getPost();
        assertThat(postOperation)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.1. Nonce Request] The Nonce endpoint MUST handle HTTP POST requests.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Response: Successful response MUST return HTTP 200 OK")
    void testNonceResponseIs200() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem).isNotNull();

        Operation postOperation = pathItem.getPost();
        assertThat(postOperation)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] POST operation must exist.")
                .isNotNull();

        ApiResponse response200 = postOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] A '200 OK' response MUST be defined for the Nonce endpoint.")
                .isNotNull();
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Content-Type: Successful response MUST use 'application/json'")
    void testNonceResponseUsesApplicationJson() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem).isNotNull();

        Operation postOperation = pathItem.getPost();
        assertThat(postOperation)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] POST operation must exist.")
                .isNotNull();

        ApiResponse response200 = postOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] A '200 OK' response MUST be defined for the Nonce endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] A successful response MUST use 'application/json' as the content type.")
                .containsKey("application/json");
    }

    // --- Tier 4: JSON Schema Assertions ---

    @Test
    @DisplayName("Schema: Response body MUST be a JSON object")
    void testNonceResponseBodyIsObject() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] A schema must be defined for the 200 application/json response.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] The Nonce Response document MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Test
    @DisplayName("Schema: 'c_nonce' MUST be a required string property")
    void testCNonceIsRequiredAndString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] The 'c_nonce' property MUST be declared as required.")
                .isNotNull()
                .contains("c_nonce");

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] Schema properties must be defined and include 'c_nonce'.")
                .isNotNull()
                .containsKey("c_nonce");
        assertThat(properties.get("c_nonce").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 7.2. Nonce Response] The 'c_nonce' property MUST be defined as a string.")
                .isNotNull()
                .contains("string");
    }

    private static Schema<?> getResponseSchema() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        return getResponseSchema(pathItem, "200");
    }
//
//    private static Schema<?> getResponseSchema() {
//        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
//        if (pathItem == null) return null;
//        Operation postOperation = pathItem.getPost();
//        if (postOperation == null) return null;
//        ApiResponse response200 = postOperation.getResponses().get("200");
//        if (response200 == null || response200.getContent() == null) return null;
//        var mediaType = response200.getContent().get("application/json");
//        if (mediaType == null) {
//            mediaType = response200.getContent().values().stream().findFirst().orElse(null);
//        }
//        if (mediaType == null) return null;
//        return mediaType.getSchema();
//    }
}
