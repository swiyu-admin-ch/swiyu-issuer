package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthAuthorizationServerMetadataDto;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Well known Controller
 * <p>
 * Implements the .well-known endpoints
 * <a href="https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html">OID4VCI Spec</a>
 * </p>
 */
@RestController
@AllArgsConstructor
@Slf4j
@Tag(name = "Well-known endpoints API", description = "Exposes OpenID .well-known endpoints for issuer configuration " +
        "and credential metadata as required by the OID4VCI specification. Provides endpoints for OpenID Connect " +
        "issuer configuration, OAuth authorization server information, and issuer metadata describing supported " +
        "verifiable credentials (IF-112)")
@RequestMapping
public class WellKnownController {

    private final JweService jweService;
    private static final String CONTENT_TYPE_APPLICATION_JWT = "application/jwt";
    private final DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private final MetadataService metadataService;

    /**
     * Returns OAuth 2.0 / OpenID Connect Authorization Server metadata.
     * <p>
     * This endpoint is an OpenAPI description for the well-known URLs defined in RFC 8414 and
     * OID4VCI. It exposes issuer, token, and authorization endpoints, supported grant types, DPoP and
     * OID4VCI-specific extensions.
     * </p>
     *
     * @return {@link OAuthAuthorizationServerMetadataDto} containing the unsigned Authorization Server
     * configuration metadata, enriched with the signing algorithms supported for DPoP.
     */
    @GetMapping(value = {"/oid4vci/.well-known/openid-configuration", ".well-known/openid-configuration", "/oid4vci/.well-known/oauth-authorization-server", ".well-known/oauth-authorization-server"})
    @Operation(summary = "Retrieve OAuth 2.0 Authorization Server Metadata",
            description = "Returns the configuration metadata of the Authorization Server in accordance with RFC 8414. " +
                    "This includes URLs to endpoints (e.g., token endpoint), supported grant types, as well as " +
                    "extensions for OpenID for Verifiable Credential Issuance (OID4VCI) and DPoP."
    )
    public OAuthAuthorizationServerMetadataDto getAuthorizationServerMetadata() {
        return demonstratingProofOfPossessionService
                .addSigningAlgorithmsSupportedAndSwissprofileVersion(
                        metadataService.getUnsignedOAuthAuthorizationServerMetadata()
                );
    }

    /**
     * Data concerning OpenID4VC Issuance
     *
     * @return Issuer Metadata as defined by OID4VCI
     */
    @GetMapping(value = {"/oid4vci/.well-known/openid-credential-issuer", ".well-known/openid-credential-issuer"})
    @Operation(summary = "Information about credentials which can be issued.")
    public IssuerMetadata getIssuerMetadata() {
        // Unwrap the object from the spring cache object.
        return (IssuerMetadata) AopProxyUtils.getSingletonTarget(jweService.issuerMetadataWithEncryptionOptions());
    }

    @GetMapping(value = {"/{tenantId}/.well-known/openid-credential-issuer", "/oid4vci/{tenantId}/.well-known/openid-credential-issuer"})
    @Operation(summary = "Information about credentials which can be issued.")
    public Object getIssuerMetadataByTenantId(
            @PathVariable UUID tenantId,
            @RequestHeader("Accept") String acceptHeader) {

        if (expectsSignedResponse(acceptHeader)) {
            return metadataService.getSignedIssuerMetadata(tenantId);
        }

        return metadataService.getUnsignedIssuerMetadata(tenantId);
    }

    /**
     * Returns tenant-specific OAuth 2.0 / OpenID Connect Authorization Server metadata.
     * <p>
     * This endpoint serves the well-known configuration documents defined by RFC 8414 and OID4VCI
     * for a given tenant. Depending on the {@code Accept} header, it returns either a signed JWT
     * representation of the Authorization Server metadata or an unsigned JSON document.
     * </p>
     *
     * @param tenantId     unique identifier of the tenant whose Authorization Server configuration
     *                     should be returned.
     * @param acceptHeader value of the {@code Accept} HTTP header used to determine whether a
     *                     signed (JWT) or unsigned JSON response is expected.
     * @return signed or unsigned tenant-specific Authorization Server metadata, matching the
     *         requested content type.
     */
    @GetMapping(value = {"/{tenantId}/.well-known/openid-configuration", "/oid4vci/{tenantId}/.well-known/openid-configuration", "/oid4vci/{tenantId}/.well-known/oauth-authorization-server", "/{tenantId}/.well-known/oauth-authorization-server"})
    @Operation(
            summary = "Retrieve tenant-specific OAuth 2.0 Authorization Server Metadata",
            description = "Returns the Authorization Server configuration metadata for the given tenant in accordance with RFC 8414. " +
                    "Depending on the 'Accept' header, the response is provided either as an unsigned JSON document or as a signed JWT. " +
                    "The metadata includes issuer information, endpoint URLs (e.g., token endpoint), supported grant types and extensions " +
                    "required for OpenID for Verifiable Credential Issuance (OID4VCI) and DPoP.")
    public Object getAuthorizationServerMetadataByTenantId(
            @PathVariable UUID tenantId,
            @RequestHeader("Accept") String acceptHeader) {

        if (expectsSignedResponse(acceptHeader)) {
            return metadataService.getSignedOAuthAuthorizationServerMetadata(tenantId);
        }

        return metadataService.getUnsignedOAuthAuthorizationServerMetadata(tenantId);
    }

    private static boolean expectsSignedResponse(String acceptHeader) {
        return acceptHeader.contains(CONTENT_TYPE_APPLICATION_JWT);
    }
}