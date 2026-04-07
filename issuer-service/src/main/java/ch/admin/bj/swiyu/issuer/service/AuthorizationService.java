package ch.admin.bj.swiyu.issuer.service;

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthAccessTokenRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenGrantType;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;

/**
 * Providing a Authroization Server Services, combinding both OAuth and DPoP features scoped together.
 */
@AllArgsConstructor
@Service
public class AuthorizationService {

    private final OAuthService oauthService;
    private final DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private final NonceService nonceService;


    /**
     * Processes all things needed for the token_endpoint of an authorization server implementing 
     * pre-authorized_code and refresh_code flows, both with a DPoP header.
     * @param dpop DPoP token as provided in HTTP Request Header by the client.
     * @param oauthAccessTokenRequestDto body of the token request
     * @param request full request with anciallary headers and request target uri
     * @return
     */
    @Transactional
    public OAuthTokenDto processOAuthTokenEndpointRequest(@Nullable String dpop,
        OAuthAccessTokenRequestDto oauthAccessTokenRequestDto,
        HttpServletRequest request) {
        if (request.getParameter("tx_code") != null) {
            throw OAuthException.invalidRequest("Unsupported parameter 'tx_code'");
        }

        if (request.getParameter("client_id") != null) {
            throw OAuthException.invalidRequest("Unsupported parameter 'client_id'");
        }

        if (oauthAccessTokenRequestDto == null || oauthAccessTokenRequestDto.grant_type() == null) {
            throw OAuthException.invalidRequest("The request is missing a required parameter");
        }

        if (OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName().equals(oauthAccessTokenRequestDto.grant_type())) {
            String preauthorizedCode = oauthAccessTokenRequestDto.preauthorized_code();
            return oauthTokenPreAuthorized(dpop, request, preauthorizedCode);
        } else if (OAuthTokenGrantType.REFRESH_TOKEN.getName().equals(oauthAccessTokenRequestDto.grant_type())) {
            String refreshToken = oauthAccessTokenRequestDto.refresh_token();
            return oauthRefreshToken(dpop, request, refreshToken);
        } else {
            throw OAuthException.unsupportedGrantType("Grant type must be urn:ietf:params:oauth:grant-type:pre-authorized_code");
        }
    }


    /**
     * Extracts the access token from the authorization header
     * @param authorizationToken the full authorization property, BEARER <access_token> or DPOP <access_token>
     * @param dpop DPoP jwt in serialized form
     * @param request full http request
     * @return the access token
     */
    public String getValidatedAccessToken(String authorizationToken, String dpop, HttpServletRequest request) {
        String accessToken = oauthService.getAccessToken(authorizationToken);
        demonstratingProofOfPossessionService.validateDpop(accessToken, dpop, new ServletServerHttpRequest(request));
        return accessToken;
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

        try {
            return oauthService.refreshOAuthToken(refreshToken);
        } catch (OAuthException exc) {
            // Other endpoints calling issueOAuthToken expect an invalid token OAuthException
            // this exception is caught here and replaced with invalid grant to follow the specification
            throw OAuthException.invalidGrant("invalid refresh token");
        }
    }

    private OAuthTokenDto oauthTokenPreAuthorized(String dpop, HttpServletRequest request, String preauthorizedCode) {
        if (StringUtils.isBlank(preauthorizedCode)) {
            throw OAuthException.invalidRequest("Pre-authorized code is required");
        }
        demonstratingProofOfPossessionService.registerDpop(
                preauthorizedCode,
                dpop,
                new ServletServerHttpRequest(request));

        try {
            return oauthService.issueOAuthToken(preauthorizedCode);
        } catch (OAuthException exc) {
            // Other endpoints calling issueOAuthToken expect an invalid token OAuthException
            // this exception is caught here and replaced with invalid grant to follow the specification
            throw OAuthException.invalidGrant("invalid token");
        }
    }

    /**
     * Create a HTTP Response with a DPoP Nonce header as used for DPoP
     * and a nonce body as used for credential proofs.
     */
    public ResponseEntity<NonceResponseDto> createNonceResponse() {
        HttpHeaders headers = new HttpHeaders();
        demonstratingProofOfPossessionService.addDpopNonce(headers);
        return new ResponseEntity<>(nonceService.createNonce(), headers, HttpStatus.OK);
    }
}
