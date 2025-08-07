/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.oid4vci.*;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.service.CredentialService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
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
@Tag(name = "Issuer OID4VCI API", description = "Public OpenID for Verifiable Credential Issuance (OID4VCI) API " +
        "endpoints, including issuing OAuth tokens for credential requests, issuing verifiable credentials, " +
        "and supporting deferred credential issuance (IF-111)")
@RequestMapping(value = {"/oid4vci/api"})
public class IssuanceController {
    private static final String OID4VCI_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    private final CredentialService credentialService;
    private final NonceService nonceService;

    @Timed
    @PostMapping(value = {"/token"},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Create a Bearer token with pre-authorized code", hidden = true)
    public OAuthTokenDto oauthAccessToken(
            @RequestParam(name = "grant_type", defaultValue = OID4VCI_GRANT_TYPE) String grantType,
            @RequestParam(name = "pre-authorized_code") String preAuthCode) {

        if (preAuthCode == null || preAuthCode.isBlank()) {
            throw OAuthException.invalidRequest("Pre-authorized code is required");
        }

        if (!OID4VCI_GRANT_TYPE.equals(grantType)) {
            throw OAuthException.invalidRequest("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
        return credentialService.issueOAuthToken(preAuthCode);
    }

    @Timed
    @PostMapping(value = {"/token"}, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Submit form data",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Form data to be submitted",
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            schema = @Schema(implementation = OauthAccessTokenRequestDto.class)
                    )
            )
    )
    public OAuthTokenDto oauthAccessToken(
            @ModelAttribute OauthAccessTokenRequestDto oauthAccessTokenRequestDto) {

        if (oauthAccessTokenRequestDto == null) {
            throw OAuthException.invalidRequest("The request is missing a required parameter");
        }

        if (oauthAccessTokenRequestDto.preauthorized_code() == null || oauthAccessTokenRequestDto.preauthorized_code().isBlank()) {
            throw OAuthException.invalidRequest("Pre-authorized code is required");
        }

        if (!OID4VCI_GRANT_TYPE.equals(oauthAccessTokenRequestDto.grant_type())) {
            throw OAuthException.invalidRequest("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
        return credentialService.issueOAuthToken(oauthAccessTokenRequestDto.preauthorized_code());
    }

    @Timed
    @PostMapping(value = {"/nonce"})
    @Operation(summary = "Provide a self-contained nonce in a publicly accessible endpoint.",
            description = """
                    Provide nonces for proof of possessions in a manner not requiring the service to save it.
                    The nonce should be used only once. The nonce has a (very) limit lifetime.
                    The response should not be cached.
                    For more information see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2">OID4VCI Nonce Endpoint specification</a>
                    """)
    public NonceResponseDto createNonce() {
        return nonceService.createNonce();
    }

    @Timed
    @PostMapping(value = {"/credential"}, produces = {MediaType.APPLICATION_JSON_VALUE, "application/jwt"})
    @Operation(summary = "Collect credential associated with the bearer token with the requested credential properties.")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<String> createCredential(@RequestHeader("Authorization") String bearerToken,
                                                   @Validated @RequestBody CredentialRequestDto credentialRequestDto,
                                                   HttpServletRequest request) {

        // data needed exclusively for deferred flow -> are removed as soon as the credential is issued
        ClientAgentInfo clientInfo = new ClientAgentInfo(
                request.getRemoteAddr(),
                request.getHeader("user-agent"),
                request.getHeader("accept-language"),
                request.getHeader("accept-encoding")
        );

        var credentialEnvelope = credentialService.createCredential(credentialRequestDto, getAccessToken(bearerToken), clientInfo);

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