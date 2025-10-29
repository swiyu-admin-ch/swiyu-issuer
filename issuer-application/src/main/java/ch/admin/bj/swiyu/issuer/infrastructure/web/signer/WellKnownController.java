/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.EncryptionService;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
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

    private final EncryptionService encryptionService;
    private final MetadataService metadataService;

    /**
     * General information about the issuer
     *
     * @return OpenIdConfigurationDto as defined by OIDConnect and extended by OID4VCI
     */
    @GetMapping(value = {"/oid4vci/.well-known/openid-configuration", ".well-known/openid-configuration"})
    @Operation(summary = "OpenID Connect information required for issuing VCs")
    public OpenIdConfigurationDto getOpenIDConfiguration() {
        return metadataService.getUnsignedOpenIdConfiguration();
    }

    /**
     * OpenID Connect information for the OAuth Authorization Server
     * This endpoint is a duplicate of the getOpenIDConfiguration endpoint in order to generate a clean openapi doc
     *
     * @return OpenIdConfigurationDto as defined by OIDConnect and extended by OID4VCI
     */
    @GetMapping(value = {"/oid4vci/.well-known/oauth-authorization-server", ".well-known/oauth-authorization-server"})
    @Operation(summary = "OpenID Connect information required for issuing VCs")
    public OpenIdConfigurationDto getOpenIDConfigurationForOauthAuthServer() {
        return metadataService.getUnsignedOpenIdConfiguration();
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
        return (IssuerMetadata) AopProxyUtils.getSingletonTarget(encryptionService.issuerMetadataWithEncryptionOptions());
    }

    @GetMapping(value = {"/{tenantId}/.well-known/openid-credential-issuer", "/oid4vci/{tenantId}/.well-known/openid-credential-issuer"})
    @Operation(summary = "Information about credentials which can be issued.")
    public Object getIssuerMetadataByTenantId(
            @PathVariable UUID tenantId,
            @RequestHeader("Content-Type") String contentType) {

        if ("application/jwt".equals(contentType)) {
            return metadataService.getSignedIssuerMetadata(tenantId);
        }

        return metadataService.getUnsignedIssuerMetadata();
    }

    @GetMapping(value = {"/{tenantId}/.well-known/openid-configuration", "/oid4vci/{tenantId}/.well-known/openid-configuration"})
    @Operation(summary = "Information about credentials which can be issued.")
    public Object getOpenIdConfigurationByTenantId(
            @PathVariable UUID tenantId,
            @RequestHeader("Content-Type") String contentType) {

        if (contentType.startsWith("application/jwt")) {
            return metadataService.getSignedOpenIdConfiguration(tenantId);
        }

        return metadataService.getUnsignedOpenIdConfiguration();
    }
}