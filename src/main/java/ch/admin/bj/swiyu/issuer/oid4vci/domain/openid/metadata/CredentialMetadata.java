package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * Collection of various Credential Metadata used in and provided by the service
 */
@Data
@Builder
public class CredentialMetadata {
    /**
     * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-6.2">See SD-JWT VC Type Metadata</a>
     * for more info
     */
    private Map<String, String> vctMetadataMap;
    /**
     * <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-6.5">See SD-JWT VC JSON Schema</a>
     * and <a href="https://json-schema.org/draft/2020-12/release-notes">JSON-Schema Specification</a> for more info
     */
    private Map<String, String> jsonSchemaMap;
    /**
     * <a href="https://oca.colossi.network/">See Overlays Capture Architecture</a> for more info
     */
    private Map<String, String> overlayCaptureArchitectureMap;

}
