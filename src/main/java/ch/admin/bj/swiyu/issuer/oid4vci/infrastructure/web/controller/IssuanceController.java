/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.oid4vci.api.DeferredCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.oid4vci.api.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.oid4vci.service.CredentialService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.regex.Pattern;

/**
 * OpenID4VC Issuance Controller
 * <p>
 * Implements the OpenID4VCI defined endpoints
 * <a href="https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html">OID4VCI Spec</a>
 * </p>
 */
@RestController
@AllArgsConstructor
@Slf4j
@Tag(name = "Issuer OID4VCI", description = "OpenID for Verifiable Credential Issuance API")
@RequestMapping(value = {"/api/v1"})
public class IssuanceController {
    private static final String OID4VCI_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final CredentialService credentialService;

    /**
     * Endpoint for the wallet to fetch the token required for getting the credential
     * Does not yet support pin.
     *
     * @param grantType   should be always urn:ietf:params:oauth:grant-type:pre-authorized_code
     * @param preAuthCode single use code to get the token
     * @return OAuth Token or raises an exception
     */
    @Timed
    @PostMapping(value = {"/token"},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Collect Bearer token with pre-authorized code")
    public OAuthTokenDto oauthAccessToken(
            @RequestParam(name = "grant_type", defaultValue = OID4VCI_GRANT_TYPE) String grantType,
            @RequestParam(name = "pre-authorized_code") String preAuthCode) {

        if (!OID4VCI_GRANT_TYPE.equals(grantType)) {
            throw OAuthException.invalidRequest("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
        return credentialService.issueOAuthToken(preAuthCode);
    }

    @Timed
    @PostMapping(value = {"/credential"}, produces = {MediaType.APPLICATION_JSON_VALUE, "application/jwt"})
    @Operation(summary = "Collect credential associated with the bearer token with the requested credential properties.")
    public ResponseEntity<String> createCredential(@RequestHeader("Authorization") String bearerToken,
                                                   @Validated @RequestBody CredentialRequestDto credentialRequestDto) {

        var credentialEnvelope = credentialService.createCredential(credentialRequestDto, getAccessToken(bearerToken));

        var headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, credentialEnvelope.getContentType());
        return ResponseEntity.ok()
                .headers(headers)
                .body(credentialEnvelope.getOid4vciCredentialJson());
    }

    @Timed
    @PostMapping(value = {"/deferred_credential"}, produces = {MediaType.APPLICATION_JSON_VALUE, "application/jwt"})
    @Operation(summary = "Collect credential associated with the bearer token and the transaction id. This endpoint is used for deferred issuance.")
    public ResponseEntity<String> createDeferredCredential(@RequestHeader("Authorization") String bearerToken,
                                                           @Valid @RequestBody DeferredCredentialRequestDto deferredCredentialRequestDto) {

        var credentialEnvelope = credentialService.createCredentialFromDeferredRequest(deferredCredentialRequestDto, getAccessToken(bearerToken));

        var headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, credentialEnvelope.getContentType());
        return ResponseEntity.ok()
                .headers(headers)
                .body(credentialEnvelope.getOid4vciCredentialJson());
    }

    private String getAccessToken(String bearerToken) {
        if (bearerToken == null) {
            throw OAuthException.invalidRequest("No authorization header found");
        }
        var regexPattern = Pattern.compile("bearer (.*)", Pattern.CASE_INSENSITIVE);
        var matcher = regexPattern.matcher(bearerToken);
        if (!matcher.find()) {
            throw OAuthException.invalidRequest("No bearer token found");
        }

        return matcher.group(1);
    }
}