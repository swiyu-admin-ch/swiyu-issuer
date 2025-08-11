/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.oid4vci.*;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialRequestDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialResponseDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.DeferredDataDtoV2;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.service.CredentialService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
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
    private final Validator validator;
    private final ObjectMapper objectMapper;

    @Timed
    @PostMapping(value = {"/token"},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Create a Bearer token with pre-authorized code", hidden = true)
    public OAuthTokenDto oauthAccessToken(
            @RequestParam(name = "grant_type", defaultValue = OID4VCI_GRANT_TYPE) String grantType,
            @RequestParam(name = "pre-authorized_code") String preAuthCode) {

        if (StringUtils.isBlank(preAuthCode)) {
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

        if (StringUtils.isBlank(oauthAccessTokenRequestDto.preauthorized_code())) {
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
    @Operation(
            summary = "Collect credential associated with the bearer token with the requested credential properties.",
            description = "Issues a credential for a given bearer token and credential request. Supports API versioning via SWIYU-API-Version header. Returns the issued credential in JSON or JWT format.",
            parameters = {
                    @Parameter(
                            name = "Authorization",
                            description = "Bearer token for authentication. Format: 'Bearer ...",
                            required = true,
                            in = ParameterIn.HEADER
                    ),
                    @Parameter(
                            name = "SWIYU-API-Version",
                            description = "Optional API version, set to '2' for v2 requests",
                            in = ParameterIn.HEADER
                    )
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = {
                            @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialRequestDto.class, CredentialRequestDtoV2.class})
                            )
                    }
            ),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential issued successfully.",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialResponseDto.class, CredentialResponseDtoV2.class})
                            )
                    ),
                    @ApiResponse(
                            responseCode = "202",
                            description = "Successful deferred credential. The credential will be issued later",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(oneOf = {DeferredDataDto.class, DeferredDataDtoV2.class})
                            )
                    )
            }
    )
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<String> createCredential(@RequestHeader("Authorization") String bearerToken,
                                                   @RequestHeader(name = "SWIYU-API-Version", required = false) String version,
                                                   @NotNull @RequestBody String requestDto,
                                                   HttpServletRequest request) throws JsonProcessingException {

        // data needed exclusively for deferred flow -> are removed as soon as the credential is issued
        var clientInfo = getClientAgentInfo(request);

        CredentialEnvelopeDto credentialEnvelope;

        if (version != null && version.equals("2")) {
            var dto = objectMapper.readValue(requestDto, CredentialRequestDtoV2.class);
            validateRequestDtoOrThrow(dto, validator);
            credentialEnvelope = credentialService.createCredentialV2(dto, getAccessToken(bearerToken), clientInfo);
        } else {
            var dto = objectMapper.readValue(requestDto, CredentialRequestDto.class);
            validateRequestDtoOrThrow(dto, validator);

            credentialEnvelope = credentialService.createCredential(dto, getAccessToken(bearerToken), clientInfo);
        }

        var headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, credentialEnvelope.getContentType());

        return ResponseEntity.status(credentialEnvelope.getHttpStatus())
                .headers(headers)
                .body(credentialEnvelope.getOid4vciCredentialJson());
    }

    @Timed
    @PostMapping(value = {"/deferred_credential"}, consumes = {"application/json"}, produces = {MediaType.APPLICATION_JSON_VALUE, "application/jwt"})
    @Operation(
            summary = "Collect credential associated with the bearer token and the transaction id. This endpoint is used for deferred issuance.",
            description = "Issues a credential for a deferred transaction. Requires a valid bearer token and transaction details in the request body.",
            parameters = {
                    @Parameter(
                            name = "Authorization",
                            description = "Bearer token for authentication",
                            required = true,
                            in = ParameterIn.HEADER
                    ),
                    @Parameter(
                            name = "SWIYU-API-Version",
                            description = "Optional API version, set to '2' for v2 requests",
                            in = ParameterIn.HEADER
                    )
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    content = {
                            @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(oneOf = {DeferredCredentialRequestDto.class, DeferredDataDtoV2.class})
                            )
                    }
            ),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential issued successfully",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialResponseDto.class, CredentialResponseDtoV2.class})
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Invalid request or validation error"
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized"
                    )
            }
    )
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<String> createDeferredCredential(@RequestHeader("Authorization") String bearerToken,
                                                           @RequestHeader(name = "SWIYU-API-Version", required = false) String version,
                                                           @NotNull @RequestBody String deferredCredentialRequestDto) throws JsonProcessingException {

        CredentialEnvelopeDto credentialEnvelope;

        if (version != null && version.equals("2")) {
            var dto = objectMapper.readValue(deferredCredentialRequestDto, DeferredCredentialRequestDto.class);
            validateRequestDtoOrThrow(dto, validator);
            credentialEnvelope = credentialService.createCredentialFromDeferredRequestV2(dto, getAccessToken(bearerToken));
        } else {
            var dto = objectMapper.readValue(deferredCredentialRequestDto, DeferredCredentialRequestDto.class);
            validateRequestDtoOrThrow(dto, validator);

            credentialEnvelope = credentialService.createCredentialFromDeferredRequest(dto, getAccessToken(bearerToken));
        }

        var headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, credentialEnvelope.getContentType());
        return ResponseEntity.status(credentialEnvelope.getHttpStatus())
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

    private @NotNull ClientAgentInfo getClientAgentInfo(HttpServletRequest request) {
        // data needed exclusively for deferred flow -> are removed as soon as the credential is issued
        return new ClientAgentInfo(
                request.getRemoteAddr(),
                request.getHeader("user-agent"),
                request.getHeader("accept-language"),
                request.getHeader("accept-encoding")
        );
    }

    private <T> void validateRequestDtoOrThrow(T dto, Validator validator) {
        Set<ConstraintViolation<T>> violations = validator.validate(dto);
        if (!violations.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (ConstraintViolation<T> constraintViolation : violations) {
                sb.append(String.format("%s: %s", constraintViolation.getPropertyPath(), constraintViolation.getMessage()));
            }
            throw new ConstraintViolationException(sb.toString(), violations);
        }
    }
}