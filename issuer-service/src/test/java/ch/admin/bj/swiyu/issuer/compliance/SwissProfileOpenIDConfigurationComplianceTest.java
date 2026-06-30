package ch.admin.bj.swiyu.issuer.compliance;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Static Compliance Check: Swiss Profile OpenID Configuration Endpoint")
class SwissProfileOpenIDConfigurationComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String ENDPOINT = "/.well-known/openid-configuration";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/.well-known/openid-configuration' MUST exist in the contract")
    void testEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: Endpoint MUST be accessible via GET")
    void testEndpointUsesGet() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();
        assertThat(pathItem.getGet())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The Discovery endpoint MUST handle HTTP GET requests.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Response: Successful response MUST return HTTP 200 OK")
    void testResponseIs200() {
        Operation getOperation = getGetOperation();
        assertThat(getOperation)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] GET operation must exist.")
                .isNotNull();
        assertThat(getOperation.getResponses().get("200"))
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] A '200 OK' response MUST be defined for the Discovery endpoint.")
                .isNotNull();
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Content-Type: Successful response MUST use 'application/json'")
    void testResponseContentTypeIsApplicationJson() {
        Operation getOperation = getGetOperation();
        assertThat(getOperation).isNotNull();
        ApiResponse response200 = getOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] A '200 OK' response must be defined.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The Discovery endpoint MUST return the response with the 'application/json' content type.")
                .containsKey("application/json");
    }

    // --- Security & Request Body Assertions ---

    @Test
    @DisplayName("Security: Endpoint MUST NOT require authentication (publicly accessible)")
    void testNoSecurityRequirement() {
        Operation getOperation = getGetOperation();
        assertThat(getOperation).isNotNull();
        assertThat(getOperation.getSecurity())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 4.1] The Discovery endpoint MUST be publicly accessible and MUST NOT require an Authorization header or any other authentication scheme.")
                .isNullOrEmpty();
    }

    @Test
    @DisplayName("Request Body: GET endpoint MUST NOT define a request body")
    void testNoRequestBody() {
        Operation getOperation = getGetOperation();
        assertThat(getOperation).isNotNull();
        assertThat(getOperation.getRequestBody())
                .as("[Document: RFC 7231, Chapter: 4.3.1] A GET request MUST NOT carry a request body.")
                .isNull();
    }

    // --- Tier 4: JSON Schema Assertions ---

    @Test
    @DisplayName("Schema: Response body MUST be a JSON object")
    void testResponseBodyIsObject() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] A schema must be defined for the 200 response.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The Discovery response MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'issuer' MUST be a required string property")
    void testIssuerIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The response schema MUST define the 'issuer' property.")
                .isNotNull()
                .containsKey("issuer");
        assertThat(properties.get("issuer").getTypes())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'issuer' property MUST be defined as a string (HTTPS URL).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'issuer' property MUST be declared as required.")
                .isNotNull()
                .contains("issuer");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'authorization_endpoint' MUST be a required string property")
    void testAuthorizationEndpointIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The response schema MUST define the 'authorization_endpoint' property.")
                .isNotNull()
                .containsKey("authorization_endpoint");
        assertThat(properties.get("authorization_endpoint").getTypes())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'authorization_endpoint' property MUST be defined as a string (URL).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'authorization_endpoint' property MUST be declared as required.")
                .isNotNull()
                .contains("authorization_endpoint");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'token_endpoint' MUST be a required string property")
    void testTokenEndpointIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The response schema MUST define the 'token_endpoint' property.")
                .isNotNull()
                .containsKey("token_endpoint");
        assertThat(properties.get("token_endpoint").getTypes())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'token_endpoint' property MUST be defined as a string (URL).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'token_endpoint' property MUST be declared as required.")
                .isNotNull()
                .contains("token_endpoint");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'jwks_uri' MUST be a required string property")
    void testJwksUriIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The response schema MUST define the 'jwks_uri' property.")
                .isNotNull()
                .containsKey("jwks_uri");
        assertThat(properties.get("jwks_uri").getTypes())
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'jwks_uri' property MUST be defined as a string (URL).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID Connect Discovery 1.0, Chapter: 3] The 'jwks_uri' property MUST be declared as required.")
                .isNotNull()
                .contains("jwks_uri");
    }

    @Test
    @DisplayName("Schema: 'response_types_supported' is OPTIONAL in OID4VCI context; if present MUST be an array and MUST NOT be required")
    void testResponseTypesSupportedIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("response_types_supported")) {
            assertThat(properties.get("response_types_supported").getTypes())
                    .as("[Document: OID4VCI, Chapter: 11; OpenID Connect Discovery 1.0, Chapter: 3] 'response_types_supported' is an OIDC-specific field not required for a pure OID4VCI Credential Issuer. If present, it MUST be of type 'array'.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OID4VCI, Chapter: 11] 'response_types_supported' is OPTIONAL in a pure OID4VCI context and MUST NOT be declared as required.")
                    .doesNotContain("response_types_supported");
        }
    }

    @Test
    @DisplayName("Schema: 'subject_types_supported' is OPTIONAL in OID4VCI context; if present MUST be an array and MUST NOT be required")
    void testSubjectTypesSupportedIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("subject_types_supported")) {
            assertThat(properties.get("subject_types_supported").getTypes())
                    .as("[Document: OID4VCI, Chapter: 11; OpenID Connect Discovery 1.0, Chapter: 3] 'subject_types_supported' is an OIDC-specific field not required for a pure OID4VCI Credential Issuer. If present, it MUST be of type 'array'.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OID4VCI, Chapter: 11] 'subject_types_supported' is OPTIONAL in a pure OID4VCI context and MUST NOT be declared as required.")
                    .doesNotContain("subject_types_supported");
        }
    }

    @Test
    @DisplayName("Schema: 'id_token_signing_alg_values_supported' is OPTIONAL in OID4VCI context; if present MUST be an array and MUST NOT be required")
    void testIdTokenSigningAlgValuesSupportedIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("id_token_signing_alg_values_supported")) {
            assertThat(properties.get("id_token_signing_alg_values_supported").getTypes())
                    .as("[Document: OID4VCI, Chapter: 11; OpenID Connect Discovery 1.0, Chapter: 3] 'id_token_signing_alg_values_supported' is an OIDC-specific field not required for a pure OID4VCI Credential Issuer. If present, it MUST be of type 'array'.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OID4VCI, Chapter: 11] 'id_token_signing_alg_values_supported' is OPTIONAL in a pure OID4VCI context and MUST NOT be declared as required.")
                    .doesNotContain("id_token_signing_alg_values_supported");
        }
    }

    @Test
    @DisplayName("Schema: 'grant_types_supported' is OPTIONAL; if present MUST be an array and MUST NOT be required")
    void testGrantTypesSupportedIsArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("grant_types_supported")) {
            assertThat(properties.get("grant_types_supported").getTypes())
                    .as("[Document: RFC 8414, Section: 2] If 'grant_types_supported' is defined, it MUST be of type 'array'. If absent, the default value [\"authorization_code\", \"implicit\"] is assumed.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: RFC 8414, Section: 2] The 'grant_types_supported' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("grant_types_supported");
        }
    }

    @Test
    @DisplayName("Schema: 'dpop_signing_alg_values_supported' is OPTIONAL; if present MUST be an array and MUST NOT be required")
    void testDpopSigningAlgValuesSupportedIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("dpop_signing_alg_values_supported")) {
            assertThat(properties.get("dpop_signing_alg_values_supported").getTypes())
                    .as("[Document: Swiss Profile Issuance, Appendix D] If 'dpop_signing_alg_values_supported' is defined, it MUST be of type 'array'.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: Swiss Profile Issuance, Appendix D] The 'dpop_signing_alg_values_supported' property is OPTIONAL and MUST NOT be declared as required. If absent, the supported algorithms are assumed to be those listed under Cryptography in the Swiss Profile.")
                    .doesNotContain("dpop_signing_alg_values_supported");
        }
    }

    @Test
    @DisplayName("Schema: 'registration_endpoint' MUST NOT be present (dynamic client registration excluded by Swiss Profile)")
    void testRegistrationEndpointIsAbsent() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema).isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            assertThat(properties)
                    .as("[Document: Swiss Profile Issuance, Chapter: 5.2] The 'registration_endpoint' MUST NOT be present in the response schema — dynamic client registration is explicitly excluded in the Swiss Profile.")
                    .doesNotContainKey("registration_endpoint");
        }
    }

    // --- Helper Methods ---

    private static Operation getGetOperation() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        if (pathItem == null) return null;
        return pathItem.getGet();
    }

    private static Schema<?> getResponseSchema() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        return getResponseSchema(pathItem, "200");
    }

}
