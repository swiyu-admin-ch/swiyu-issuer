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

@DisplayName("Static Compliance Check: Swiss Profile OCA Endpoint")
class SwissProfileOcaComplianceTest extends AbstractSwissProfileComplianceTest {

    private static final String MAPPING_PATH = "/oid4vci";
    private static final String ENDPOINT = MAPPING_PATH + "/oca/{ocaKey}";

    // --- Tier 1: Path Item Verification ---

    @Test
    @DisplayName("Path: Endpoint '/oid4vci/oca/{ocaKey}' must exist in the contract")
    void testOcaEndpointExists() {
        assertThat(openAPI.getPaths())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] The paths section must not be empty.")
                .isNotNull();
        assertThat(openAPI.getPaths().get(ENDPOINT))
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] The endpoint " + ENDPOINT + " MUST exist in the OpenAPI contract.")
                .isNotNull();
    }

    // --- Tier 2: HTTP Verb Validation ---

    @Test
    @DisplayName("HTTP Verb: OCA Bundle MUST be retrieved via GET")
    void testOcaEndpointUsesGet() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation getOperation = pathItem.getGet();
        assertThat(getOperation)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] Retrieval of an OCA Bundle MUST be performed via the HTTP GET method.")
                .isNotNull();
    }

    // --- Tier 3: Response Status & Media Type Check ---

    @Test
    @DisplayName("Content-Type: OCA Bundle MUST be served with 'application/json'")
    void testOcaResponseUsesApplicationJson() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        assertThat(pathItem)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] Path item for " + ENDPOINT + " must exist.")
                .isNotNull();

        Operation getOperation = pathItem.getGet();
        assertThat(getOperation)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] GET operation must exist.")
                .isNotNull();

        ApiResponse response200 = getOperation.getResponses().get("200");
        assertThat(response200)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] A '200 OK' response MUST be defined for the OCA endpoint.")
                .isNotNull();

        assertThat(response200.getContent())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] The 200 response MUST define content.")
                .isNotNull();
        assertThat(response200.getContent())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle reference in Verifiable Credentials / SD-JWT VC] The OCA Bundle MUST be associated with 'application/json' when retrieved via a URL.")
                .containsKey("application/json");
    }

    // --- Tier 4: JSON Schema Assertions ---

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: OCA Bundle response MUST be a JSON object")
    void testOcaResponseBodyIsObject() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] A schema must be defined for the 200 application/json response.")
                .isNotNull();
        assertThat(schema.getTypes())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] The OCA Bundle MUST be represented as a single valid JSON object.")
                .isNotNull()
                .contains("object");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'capture_bases' MUST be a required array containing Capture Base objects")
    void testCaptureBasesIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] Schema properties must be defined and include 'capture_bases'.")
                .isNotNull()
                .containsKey("capture_bases");

        assertThat(properties.get("capture_bases").getTypes())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] The 'capture_bases' property MUST be of type 'array'.")
                .isNotNull()
                .contains("array");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] The 'capture_bases' property MUST be declared as required.")
                .isNotNull()
                .contains("capture_bases");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'overlays' MUST be a required array (may be empty)")
    void testOverlaysIsRequiredArray() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] Schema properties must be defined and include 'overlays'.")
                .isNotNull()
                .containsKey("overlays");

        assertThat(properties.get("overlays").getTypes())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] The 'overlays' property MUST be of type 'array'.")
                .isNotNull()
                .contains("array");

        List<String> required = schema.getRequired();
        assertThat(required)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: OCA Bundle as JSON file] The 'overlays' property MUST be declared as required.")
                .isNotNull()
                .contains("overlays");
    }

    @Test
    @DisplayName("Schema: Capture Base MUST NOT allow 'classification' (NOT SUPPORTED in Swiss Profile)")
    void testCaptureBaseClassificationIsNotSupported() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Attributes] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Schema<?> captureBaseItemSchema = getCaptureBaseItemSchema(schema);
        if (captureBaseItemSchema == null) return;

        Map<String, Schema> captureBaseProperties = captureBaseItemSchema.getProperties();
        if (captureBaseProperties != null) {
            assertThat(captureBaseProperties)
                    .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Attributes] The 'classification' attribute MUST NOT be present in the Capture Base schema — it is NOT SUPPORTED in the Swiss Profile.")
                    .doesNotContainKey("classification");
        }
    }

    @Test
    @DisplayName("Schema: Capture Base MUST NOT allow 'flagged_attributes' (NOT SUPPORTED in Swiss Profile)")
    void testCaptureBaseFlaggedAttributesIsNotSupported() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Attributes] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Schema<?> captureBaseItemSchema = getCaptureBaseItemSchema(schema);
        if (captureBaseItemSchema == null) return;

        Map<String, Schema> captureBaseProperties = captureBaseItemSchema.getProperties();
        if (captureBaseProperties != null) {
            assertThat(captureBaseProperties)
                    .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Attributes] The 'flagged_attributes' attribute MUST NOT be present in the Capture Base schema — it is NOT SUPPORTED in the Swiss Profile.")
                    .doesNotContainKey("flagged_attributes");
        }
    }

    @Test
    @DisplayName("Schema: Branding Overlay MUST define a 'theme' attribute for dark mode support")
    void testBrandingOverlayDefinesThemeAttribute() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Aries Branding Overlay update] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        if (properties == null) return;

        Schema<?> overlaysSchema = properties.get("overlays");
        if (overlaysSchema == null || overlaysSchema.getItems() == null) return;

        Schema<?> overlayItemSchema = overlaysSchema.getItems();
        Map<String, Schema> overlayProperties = overlayItemSchema.getProperties();
        if (overlayProperties == null) return;

        assertThat(overlayProperties)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Aries Branding Overlay update] The Branding Overlay MUST define a 'theme' attribute, which MUST be explicitly set to 'dark' to handle proper visualization in dark mode.")
                .containsKey("theme");
    }

    @Disabled("TODO EIDOMNI-1127: Fixing Compliance OID4VCI / Swiss profile")
    @Test
    @DisplayName("Schema: 'Data Source Mapping Overlay' MUST be supported to map Capture Base attributes to VC data paths")
    void testDataSourceMappingOverlayIsSupported() {
        Schema<?> schema = getResponseSchema();
        assertThat(schema)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Data Source Mapping Overlay] A schema must be defined for the 200 application/json response.")
                .isNotNull();

        Map<String, Schema> properties = schema.getProperties();
        assertThat(properties)
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Data Source Mapping Overlay] Schema must define properties including 'overlays'.")
                .isNotNull()
                .containsKey("overlays");

        Schema<?> overlaysSchema = properties.get("overlays");
        assertThat(overlaysSchema.getItems())
                .as("[Document: Overlays Capture Architecture (OCA) 1.0 - swiyu technical documentation, Chapter: Data Source Mapping Overlay] The 'overlays' array MUST define an item schema to support the Data Source Mapping Overlay, which maps Capture Base attributes to their corresponding data paths in the Verifiable Credential.")
                .isNotNull();
    }

    private static Schema<?> getResponseSchema() {
        PathItem pathItem = openAPI.getPaths().get(ENDPOINT);
        return getResponseSchema(pathItem, "200");
    }

    private static Schema<?> getCaptureBaseItemSchema(Schema<?> rootSchema) {
        if (rootSchema == null) return null;
        Map<String, Schema> properties = rootSchema.getProperties();
        if (properties == null) return null;
        Schema<?> captureBasesSchema = properties.get("capture_bases");
        if (captureBasesSchema == null) return null;
        return captureBasesSchema.getItems();
    }
}
