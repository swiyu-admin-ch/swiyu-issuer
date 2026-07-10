package ch.admin.bj.swiyu.issuer.compliance;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Static Compliance Check: Swiss Profile JSON Schema Endpoint")
class SwissProfileJsonSchemaComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/json-schema/{schemaKey}";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/json-schema/{schemaKey}' must exist in the contract")
    void testJsonSchemaEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: JSON Schema MUST be retrieved via GET")
    void testJsonSchemaEndpointUsesGet() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation getOperation = pathItem.getGet();
        assertThat(getOperation)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] Retrieval of a JSON Schema MUST be performed via the HTTP GET method.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Content-Type: Successful response MUST use 'application/schema+json'")
    void testJsonSchemaResponseUsesApplicationSchemaJson() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation getOperation = pathItem.getGet();
        assertThat(getOperation)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] GET operation must exist.")
                .isNotNull();

        ApiResponse response200 = getOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] A '200 OK' response MUST be defined for the JSON Schema endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] The JSON Schema endpoint MUST use 'application/schema+json' to support privacy-preserving local caching for Wallets.")
                .containsKey("application/schema+json");
    }

    @Test
    @DisplayName("Caching: The endpoint must not define 'application/json' as the sole media type — schema+json enables cache-based retrieval")
    void testJsonSchemaDoesNotUsePlainApplicationJson() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        if (pathItem == null) return;
        Operation getOperation = pathItem.getGet();
        if (getOperation == null) return;
        ApiResponse response200 = getOperation.getResponses().get("200");
        if (response200 == null || response200.getContent() == null) return;

        boolean hasSchemaJson = response200.getContent().containsKey("application/schema+json");
        boolean hasOnlyPlainJson = response200.getContent().containsKey("application/json") && !hasSchemaJson;

        assertThat(hasOnlyPlainJson)
                .as("[Document: draft-ietf-oauth-sd-jwt-vc-15, Chapter: 5.3.4. From a Local Cache] The JSON Schema endpoint MUST NOT exclusively use 'application/json' — 'application/schema+json' is required to enable privacy-preserving local caching for Wallets.")
                .isFalse();
    }
}
