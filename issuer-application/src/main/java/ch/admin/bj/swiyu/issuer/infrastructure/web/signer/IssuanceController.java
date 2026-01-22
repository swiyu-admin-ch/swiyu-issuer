/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.api.oid4vci.*;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointResponseDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.DeferredDataDtoV2;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.service.*;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.EncryptionJweService;
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
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import jakarta.validation.Validator;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
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
    public static final String API_VERSION_OID4VCI_1_0 = "2";
    public static final String DPOP_HTTP_HEADER = "DPoP";
    public static final String SWIYU_API_VERSION_HTTP_HEADER = "SWIYU-API-Version";

    private final CredentialServiceOrchestrator credentialServiceOrchestrator;
    private final NonceService nonceService;
    private final EncryptionJweService encryptionJweService;
    private final OAuthService oauthService;
    private final DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;

    private final Validator validator;
    private final ObjectMapper objectMapper;


    @Deprecated(forRemoval = true)
    @Timed
    @PostMapping(value = {"/token"},
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Create a Bearer token with pre-authorized code", hidden = true)
    public OAuthTokenDto oauthTokenEndpoint(
            @RequestHeader(name = DPOP_HTTP_HEADER, required = false) String dpop,
            @RequestParam(name = "grant_type") @NotEmpty String grantType,
            @RequestParam(name = "pre-authorized_code") @Nullable String preAuthCode,
            @RequestParam(name = "refresh_token") @Nullable String refreshToken,
            HttpServletRequest request) {

        if (OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName().equals(grantType)) {
            return oauthTokenPreAuthorized(dpop, request, preAuthCode);
        } else if (OAuthTokenGrantType.REFRESH_TOKEN.getName().equals(grantType)) {
            return oauthRefreshToken(dpop, request, refreshToken);
        } else {
            throw OAuthException.invalidRequest("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
    }

    @Timed
    @PostMapping(value = {"/token"}, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Submit form data",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "OAuth 2.0 access token request to be submitted",
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            schema = @Schema(implementation = OAuthAccessTokenRequestDto.class)
                    )
            )
    )
    public OAuthTokenDto oauthTokenEndpoint(
            @RequestHeader(name = DPOP_HTTP_HEADER, required = false) String dpop,
            @ModelAttribute OAuthAccessTokenRequestDto oauthAccessTokenRequestDto,
            HttpServletRequest request) {

        if (oauthAccessTokenRequestDto == null) {
            throw OAuthException.invalidRequest("The request is missing a required parameter");
        }

        if (OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName().equals(oauthAccessTokenRequestDto.grant_type())) {
            String preauthorizedCode = oauthAccessTokenRequestDto.preauthorized_code();
            return oauthTokenPreAuthorized(dpop, request, preauthorizedCode);
        } else if (OAuthTokenGrantType.REFRESH_TOKEN.getName().equals(oauthAccessTokenRequestDto.grant_type())) {
            String refreshToken = oauthAccessTokenRequestDto.refresh_token();
            return oauthRefreshToken(dpop, request, refreshToken);
        } else {
            throw OAuthException.invalidRequest("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
    }

    @Timed
    @PostMapping(value = {"/nonce"})
    @Operation(summary = "Provide a self-contained nonce in a publicly accessible endpoint.",
            description = """
                    Provide nonces for proof of possessions in a manner not requiring the service to save it.
                    The nonce should be used only once. The nonce has a (very) limit lifetime.
                    The response should not be cached.
                    For more information see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2">OID4VCI Nonce Endpoint specification</a></br>
                    Also provides a DPoP nonce. For more details towards demonstrating proof of possession refer to <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
                    """)
    public ResponseEntity<NonceResponseDto> createNonce() {
        HttpHeaders headers = new HttpHeaders();
        demonstratingProofOfPossessionService.addDpopNonce(headers);
        return new ResponseEntity<>(nonceService.createNonce(), headers, HttpStatus.OK);
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
                            name = SWIYU_API_VERSION_HTTP_HEADER,
                            description = "Optional API version, set to '2' for v2 requests",
                            in = ParameterIn.HEADER
                    )
            },
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = {
                            @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialEndpointRequestDto.class, CredentialEndpointRequestDtoV2.class})
                            ),
                            @Content(
                                    mediaType = "application/jwt", // See: OID4VCI 1.0 Chapter 10
                                    schema = @Schema(implementation = String.class, description = """
                                            An encoded JWT as described in RFC7519, with the claims as found in the unencrypted request
                                            """)
                            )
                    }
            ),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential issued successfully.",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialEndpointResponseDto.class, CredentialEndpointResponseDtoV2.class})
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
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<String> createCredential(@RequestHeader("Authorization") String bearerToken,
                                                   @RequestHeader(name = SWIYU_API_VERSION_HTTP_HEADER, required = false) String version,
                                                   @RequestHeader(name = DPOP_HTTP_HEADER, required = false) String dpop,
                                                   @NotNull @RequestBody String requestDto,
                                                   HttpServletRequest request) throws IOException {
        String requestString = requestDto;
        // Decrypt if holder sent an encrypted
        if (StringUtils.equalsIgnoreCase("application/jwt", request.getContentType())) {
            requestString = encryptionJweService.decrypt(requestDto);
        } else if (encryptionJweService.isRequestEncryptionMandatory()) {
            throw new IllegalArgumentException("Credential Request must be encrypted");
        }

        // data needed exclusively for deferred flow -> are removed as soon as the credential is issued
        var clientInfo = getClientAgentInfo(request);

        CredentialEnvelopeDto credentialEnvelope;

        String accessToken = getAccessToken(bearerToken);
        demonstratingProofOfPossessionService.validateDpop(accessToken, dpop, new ServletServerHttpRequest(request));

        if (API_VERSION_OID4VCI_1_0.equals(version)) {
            var dto = objectMapper.readValue(requestString, CredentialEndpointRequestDtoV2.class);
            validateRequestDtoOrThrow(dto, validator);
            credentialEnvelope = credentialServiceOrchestrator.createCredentialV2(dto, accessToken, clientInfo, dpop);
        } else {
            var dto = objectMapper.readValue(requestString, CredentialEndpointRequestDto.class);
            validateRequestDtoOrThrow(dto, validator);

            credentialEnvelope = credentialServiceOrchestrator.createCredential(dto, accessToken, clientInfo);
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
                            name = SWIYU_API_VERSION_HTTP_HEADER,
                            description = "Optional API version, set to '2' for v2 requests",
                            in = ParameterIn.HEADER
                    )
            },
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential issued successfully",
                            content = @Content(
                                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                                    schema = @Schema(oneOf = {CredentialEndpointResponseDto.class, CredentialEndpointResponseDtoV2.class})
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
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<String> createDeferredCredential(@RequestHeader("Authorization") String bearerToken,
                                                           @RequestHeader(name = SWIYU_API_VERSION_HTTP_HEADER, required = false) String version,
                                                           @RequestHeader(name = DPOP_HTTP_HEADER, required = false) String dpop,
                                                           @Valid @RequestBody DeferredCredentialEndpointRequestDto deferredCredentialRequestDto,
                                                           HttpServletRequest request) {

        CredentialEnvelopeDto credentialEnvelope;

        String accessToken = getAccessToken(bearerToken);
        demonstratingProofOfPossessionService.validateDpop(accessToken, dpop, new ServletServerHttpRequest(request));
        if (API_VERSION_OID4VCI_1_0.equals(version)) {
            credentialEnvelope = credentialServiceOrchestrator.createCredentialFromDeferredRequestV2(deferredCredentialRequestDto, accessToken);
        } else {
            credentialEnvelope = credentialServiceOrchestrator.createCredentialFromDeferredRequest(deferredCredentialRequestDto, accessToken);
        }

        var headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, credentialEnvelope.getContentType());
        return ResponseEntity.status(credentialEnvelope.getHttpStatus())
                .headers(headers)
                .body(credentialEnvelope.getOid4vciCredentialJson());
    }

    private OAuthTokenDto oauthRefreshToken(String dpop, HttpServletRequest request, String refreshToken) {
        if (StringUtils.isBlank(refreshToken)) {
            throw OAuthException.invalidRequest("Refresh Token is required");
        }
        demonstratingProofOfPossessionService.refreshDpop(
                refreshToken,
                dpop,
                new ServletServerHttpRequest(request)
        );
        return oauthService.refreshOAuthToken(refreshToken);
    }

    private OAuthTokenDto oauthTokenPreAuthorized(String dpop, HttpServletRequest request, String preauthorizedCode) {
        if (StringUtils.isBlank(preauthorizedCode)) {
            throw OAuthException.invalidRequest("Pre-authorized code is required");
        }
        demonstratingProofOfPossessionService.registerDpop(
                preauthorizedCode,
                dpop,
                new ServletServerHttpRequest(request));
        return oauthService.issueOAuthToken(preauthorizedCode);
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