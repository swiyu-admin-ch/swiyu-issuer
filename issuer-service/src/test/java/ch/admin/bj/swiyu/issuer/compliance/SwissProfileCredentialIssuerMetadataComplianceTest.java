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

@DisplayName("Static Compliance Check: Swiss Profile Credential Issuer Metadata Endpoint")
class SwissProfileCredentialIssuerMetadataComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/.well-known/openid-credential-issuer";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/.well-known/openid-credential-issuer' must exist in the contract")
    void testCredentialIssuerMetadataEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: Credential Issuer Metadata MUST be retrieved via GET")
    void testCredentialIssuerMetadataEndpointUsesGet() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        assertThat(pathItem.getGet())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] The Credential Issuer Metadata MUST be retrieved via HTTP GET.")
                .isNotNull();
    }

    @Test
    @DisplayName("HTTP Verb: Credential Issuer Metadata endpoint MUST NOT define a request body")
    void testCredentialIssuerMetadataHasNoRequestBody() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        if (pathItem == null) return;
        Operation getOperation = pathItem.getGet();
        if (getOperation == null) return;

        assertThat(getOperation.getRequestBody())
                .as("[Document: RFC 7231, Chapter: 4.3.1] The endpoint MUST NOT define a requestBody — GET requests carry no payload.")
                .isNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Content-Type: Successful response MUST use 'application/json'")
    void testCredentialIssuerMetadataResponseUsesApplicationJson() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation getOperation = pathItem.getGet();
        assertThat(getOperation)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] GET operation must exist.")
                .isNotNull();

        ApiResponse response200 = getOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] A '200 OK' response MUST be defined for the Credential Issuer Metadata endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.2] The Credential Issuer Metadata MUST be delivered with 'application/json'. A wildcard media type ('*/*') is not a valid explicit declaration.")
                .containsKey("application/json");
    }

    // --- Tier 4: JSON Schema Assertions ---

    @Test
    @DisplayName("Schema: Response body MUST be a JSON object")
    void testCredentialIssuerMetadataResponseBodyIsObject() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The Credential Issuer Metadata MUST be formatted as a JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Test
    @DisplayName("Schema: 'credential_issuer' MUST be a required string property")
    void testCredentialIssuerIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for VerifiablCredentialIssuerMetadataSpec.mde Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] Schema properties must be defined and include 'credential_issuer'.")
                .isNotNull()
                .containsKey("credential_issuer");
        assertThat(properties.get("credential_issuer").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_issuer' property MUST be of type 'string' (HTTPS URL identifying the Credential Issuer).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_issuer' property MUST be declared as required.")
                .isNotNull()
                .contains("credential_issuer");
    }

    @Test
    @DisplayName("Schema: 'credential_endpoint' MUST be a required string property")
    void testCredentialEndpointIsRequiredString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] Schema properties must be defined and include 'credential_endpoint'.")
                .isNotNull()
                .containsKey("credential_endpoint");
        assertThat(properties.get("credential_endpoint").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_endpoint' property MUST be of type 'string' (URL of the Credential Endpoint).")
                .isNotNull()
                .contains("string");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_endpoint' property MUST be declared as required.")
                .isNotNull()
                .contains("credential_endpoint");
    }

    @Test
    @DisplayName("Schema: 'credential_configurations_supported' MUST be a required object (map of credential configurations)")
    void testCredentialConfigurationsSupportedIsRequiredObject() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] Schema properties must be defined and include 'credential_configurations_supported'.")
                .isNotNull()
                .containsKey("credential_configurations_supported");
        assertThat(properties.get("credential_configurations_supported").getTypes())
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_configurations_supported' property MUST be of type 'object' (a map from credential type identifier to configuration object).")
                .isNotNull()
                .contains("object");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'credential_configurations_supported' property MUST be declared as required.")
                .isNotNull()
                .contains("credential_configurations_supported");
    }

    @Test
    @DisplayName("Schema: Each credential configuration MUST define 'format' as a required property")
    void testCredentialConfigurationFormatIsRequired() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties == null || !properties.containsKey("credential_configurations_supported")) return;

        Schema<?> configMapSchema = properties.get("credential_configurations_supported");
        Schema<?> configItemSchema = configMapSchema.getAdditionalProperties() instanceof Schema<?>
                ? (Schema<?>) configMapSchema.getAdditionalProperties()
                : null;
        if (configItemSchema == null) return;

        Map<String, Schema> configProperties = configItemSchema.getProperties();
        assertThat(configProperties)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] Each credential configuration in 'credential_configurations_supported' MUST define a 'format' property.")
                .isNotNull()
                .containsKey("format");

        List<String> configRequired = configItemSchema.getRequired();
        assertThat(configRequired)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'format' property MUST be declared as required within each credential configuration.")
                .isNotNull()
                .contains("format");
    }

    @Test
    @DisplayName("Schema: Each credential configuration MUST define 'protected_issuance_authorization_trust_statement' as required")
    void testCredentialConfigurationTrustStatementIsRequired() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Swiss Profile Trust, Chapter: Trust Markers] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties == null || !properties.containsKey("credential_configurations_supported")) return;

        Schema<?> configMapSchema = properties.get("credential_configurations_supported");
        Schema<?> configItemSchema = configMapSchema.getAdditionalProperties() instanceof Schema<?>
                ? (Schema<?>) configMapSchema.getAdditionalProperties()
                : null;
        if (configItemSchema == null) return;

        Map<String, Schema> configProperties = configItemSchema.getProperties();
        assertThat(configProperties)
                .as("[Document: Swiss Profile Trust, Chapter: Trust Markers] Each credential configuration MUST define 'protected_issuance_authorization_trust_statement' to prove issuance authorization for protected VC formats.")
                .isNotNull()
                .containsKey("protected_issuance_authorization_trust_statement");

    }

    @Test
    @DisplayName("Schema: 'credential_issuer_identity_trust_statement' MUST be a required string property")
    void testCredentialIssuerIdentityTrustStatementIsRequired() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Swiss Profile Trust, Chapter: Trust Markers] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: Swiss Profile Trust, Chapter: Trust Markers] Schema properties must be defined and include 'credential_issuer_identity_trust_statement'.")
                .isNotNull()
                .containsKey("credential_issuer_identity_trust_statement");
        assertThat(properties.get("credential_issuer_identity_trust_statement").getTypes())
                .as("[Document: Swiss Profile Trust, Chapter: Trust Markers] The 'credential_issuer_identity_trust_statement' property MUST be of type 'string' (a JWT proving the issuer's identity within the Swiss Trust ecosystem).")
                .isNotNull()
                .contains("string");

    }

    @Test
    @DisplayName("Schema: 'authorization_servers' is OPTIONAL; if present MUST be an array and MUST NOT be required")
    void testAuthorizationServersIsOptionalArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("authorization_servers")) {
            assertThat(properties.get("authorization_servers").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] If 'authorization_servers' is defined, it MUST be of type 'array'.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'authorization_servers' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("authorization_servers");
        }
    }

    @Test
    @DisplayName("Schema: 'deferred_credential_endpoint' is OPTIONAL; if present MUST be a string and MUST NOT be required")
    void testDeferredCredentialEndpointIsOptionalString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("deferred_credential_endpoint")) {
            assertThat(properties.get("deferred_credential_endpoint").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.3] If 'deferred_credential_endpoint' is defined, it MUST be of type 'string' (URL of the Deferred Credential Endpoint).")
                    .isNotNull()
                    .contains("string");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.3] The 'deferred_credential_endpoint' is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("deferred_credential_endpoint");
        }
    }

    @Test
    @DisplayName("Schema: 'display' is OPTIONAL; if present MUST be an array and MUST NOT be required")
    void testDisplayIsOptionalArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("display")) {
            assertThat(properties.get("display").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] If 'display' is defined, it MUST be of type 'array' of display objects.")
                    .isNotNull()
                    .contains("array");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'display' property is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("display");
        }
    }

    @Test
    @DisplayName("Schema: 'notification_endpoint' is OPTIONAL; if present MUST be a string and MUST NOT be required")
    void testNotificationEndpointIsOptionalString() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null && properties.containsKey("notification_endpoint")) {
            assertThat(properties.get("notification_endpoint").getTypes())
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] If 'notification_endpoint' is defined, it MUST be of type 'string' (URL of the Notification Endpoint).")
                    .isNotNull()
                    .contains("string");
        }

        List<String> required = schema.getRequired();
        if (required != null) {
            assertThat(required)
                    .as("[Document: OpenID for Verifiable Credential Issuance 1.0, Chapter: 11.2.3] The 'notification_endpoint' is OPTIONAL and MUST NOT be declared as required.")
                    .doesNotContain("notification_endpoint");
        }
    }

    // --- Helper Methods ---

    private static Schema<?> getResponseSchema() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        return getResponseSchema(pathItem, "200");
    }
}
