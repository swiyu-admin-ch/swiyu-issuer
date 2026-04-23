package ch.admin.bj.swiyu.issuer.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.springframework.http.HttpRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import ch.admin.bj.swiyu.issuer.common.exception.OAuthError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthAccessTokenRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenGrantType;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenTypeDto;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import jakarta.servlet.http.HttpServletRequest;



class AuthorizationServiceTest {
    
    private OAuthService oAuthService;
    private DemonstratingProofOfPossessionService dpopSerivce;
    private NonceService nonceService;
    private AuthorizationService issuanceService;
    
    private HttpServletRequest httpRequest;

    @BeforeEach
    void setup() {
        oAuthService = Mockito.mock(OAuthService.class);
        dpopSerivce = Mockito.mock(DemonstratingProofOfPossessionService.class);
        nonceService = Mockito.mock(NonceService.class);
        httpRequest = Mockito.mock(HttpServletRequest.class);

        issuanceService = new AuthorizationService(oAuthService, dpopSerivce, nonceService);
    }

    @Test
    void oauthTokenEndpointWithValidPreAuthorizedCode_thenSuccess() {
        var uuid = UUID.randomUUID();
        var expectedResponse = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh")
                .tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.issueOAuthToken(uuid.toString())).thenReturn(expectedResponse);
        var requestBody = new OAuthAccessTokenRequestDto(
            OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName(), uuid.toString(), null);
        var oAuthTokenDto = issuanceService.processOAuthTokenEndpointRequest(null, requestBody, httpRequest);
        assertThat(oAuthTokenDto.getAccessToken()).isNotBlank().isEqualTo(expectedResponse.getAccessToken());
        assertThat(oAuthTokenDto.getRefreshToken()).isNotBlank().isEqualTo(expectedResponse.getRefreshToken());
    }

    @Test
    void oauthTokenEndpointWithValidRefreshToken_thenSuccess() {
        var uuid = UUID.randomUUID();
        var expectedResponse = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh")
                .tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.refreshOAuthToken(uuid.toString())).thenReturn(expectedResponse);
        var requestBody = new OAuthAccessTokenRequestDto(
            OAuthTokenGrantType.REFRESH_TOKEN.getName(), null, uuid.toString());
        var oAuthTokenDto = issuanceService.processOAuthTokenEndpointRequest(null, requestBody, httpRequest);
        assertThat(oAuthTokenDto.getAccessToken()).isNotBlank().isEqualTo(expectedResponse.getAccessToken());
        assertThat(oAuthTokenDto.getRefreshToken()).isNotBlank().isEqualTo(expectedResponse.getRefreshToken());
    }

    @Test
    void oauthTokenEndpointWithInvalidRequest_whenNoFields_thenBadRequest() {
        var expectedErrorCode = OAuthError.INVALID_REQUEST;
        var error = assertThrows(OAuthException.class, () -> issuanceService.processOAuthTokenEndpointRequest(null, null, httpRequest));
        assertThat(error.getError()).isEqualTo(expectedErrorCode);
    }

    
    @Test
    void oauthTokenEndpointWithInvalidRequest_whenRefreshWithoutRefreshToken_thenBadRequest() {
        var expectedErrorCode = OAuthError.INVALID_REQUEST;
        var requestBody = new OAuthAccessTokenRequestDto(
            OAuthTokenGrantType.REFRESH_TOKEN.getName(), UUID.randomUUID().toString(), null);
        var error = assertThrows(OAuthException.class, () -> issuanceService.processOAuthTokenEndpointRequest(null, requestBody, httpRequest));
        assertThat(error.getError()).isEqualTo(expectedErrorCode);
    }

    @Test
    void oauthTokenEndpointWithInvalidRequest_whenRegisterWithoutPreAuthCode_thenBadRequest() {
        var expectedErrorCode = OAuthError.INVALID_REQUEST;
        var requestBody = new OAuthAccessTokenRequestDto(
            OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName(), null, UUID.randomUUID().toString());
        var error = assertThrows(OAuthException.class, () -> issuanceService.processOAuthTokenEndpointRequest(null, requestBody, httpRequest));
        assertThat(error.getError()).isEqualTo(expectedErrorCode);
    }

    @Test
    void oauthtokenEndpointWithInvalidGrant_whenWrongPreAuthCode_thenBadRequest() {
        var requestBody = new OAuthAccessTokenRequestDto(
            "non-existent-grant-type", UUID.randomUUID().toString(), null);
        var error = assertThrows(OAuthException.class, () -> issuanceService.processOAuthTokenEndpointRequest(null, requestBody, httpRequest));
        assertThat(error.getError()).isEqualTo(OAuthError.UNSUPPORTED_GRANT_TYPE);
    }

}
