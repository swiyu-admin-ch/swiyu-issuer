/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.infrastructure.config.OpenIdIssuerApiConfiguration;
import ch.admin.bj.swiyu.issuer.service.EncryptionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

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
@RequestMapping(value = {"/oid4vci/.well-known", ".well-known"})
public class WellKnownController {

    private final OpenIdIssuerApiConfiguration openIDConfigurationDto;
    private final EncryptionService  encryptionService;

    /**
     * General information about the issuer
     *
     * @return OpenIdConfigurationDto as defined by OIDConnect and extended by OID4VCI
     */
    @GetMapping("/openid-configuration")
    @Operation(summary = "OpenID Connect information required for issuing VCs")
    public OpenIdConfigurationDto getOpenIDConfiguration() throws IOException {
        return openIDConfigurationDto.getOpenIdConfiguration();
    }

    /**
     * OpenID Connect information for the OAuth Authorization Server
     * This endpoint is a duplicate of the getOpenIDConfiguration endpoint in order to generate a clean openapi doc
     *
     * @return OpenIdConfigurationDto as defined by OIDConnect and extended by OID4VCI
     */
    @GetMapping("/oauth-authorization-server")
    @Operation(summary = "OpenID Connect information required for issuing VCs")
    public OpenIdConfigurationDto getOpenIDConfigurationForOauthAuthServer() throws IOException {
        return openIDConfigurationDto.getOpenIdConfiguration();
    }

    /**
     * Data concerning OpenID4VC Issuance
     *
     * @return Issuer Metadata as defined by OID4VCI
     */
    @GetMapping(value = {"/openid-credential-issuer"})
    @Operation(summary = "Information about credentials which can be issued.")
    public IssuerMetadata getIssuerMetadata() throws IOException {
        return encryptionService.addEncryptionOptions(openIDConfigurationDto.getIssuerMetadata());
    }
}