package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenGrantType;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenTypeDto;
import ch.admin.bj.swiyu.issuer.infrastructure.web.signer.IssuanceController;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.UUID;


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = IssuanceController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class IssuanceControllerTest {
    private static final String ACCESS_TOKEN = "00000000-0000-0000-0000-000000000000";

    // Mocks of the issuance controller
    @MockitoBean
    private ApplicationProperties props;
    @MockitoBean
    private NonceService nonceService;
    @MockitoBean
    private CredentialServiceOrchestrator credentialServiceOrchestrator;
    @MockitoBean
    private JweService jweService;
    @MockitoBean
    private OAuthService oAuthService;

    // Relevant mocks for the tests in this class
    @MockitoBean
    private DemonstratingProofOfPossessionService dpopService;
    @MockitoBean
    private HttpServletRequest httpRequest;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    private IssuanceController controller;
    @Autowired
    private MockMvc mvc;

    private final String tokenEndpoint = "/oid4vci/api/token";

    private static final String INVALID_REQUEST_REASON = "When the Credential Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed, the error 'invalid_credential_request' must be returned.";

    @BeforeEach
    void setup() {
        when(jweService.decryptRequest(anyString(), anyString())).then(a -> {
            return a.getArguments()[0];
        }); // Return input
        when(oAuthService.getAccessToken(anyString())).thenReturn(ACCESS_TOKEN);
        when(httpRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpRequest.getContentType()).thenReturn("application/json");
        when(httpRequest.getAttribute(anyString())).thenReturn("Test");
    }

    @Test
    void oauthTokenEndpointWithValidPreAuthorizedCode_thenSuccess() {
        var uuid = UUID.randomUUID();
        var response = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh")
                .tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.issueOAuthToken(uuid.toString())).thenReturn(response);
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName())
                        .param("pre-authorized_code", uuid.toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").value(response.getAccessToken()))
                .andExpect(jsonPath("$.refresh_token").value(response.getRefreshToken())));
    }

    @Test
    void oauthTokenEndpointWithValidRefreshToken_thenSuccess() {
        var uuid = UUID.randomUUID();
        var response = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh")
                .tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.refreshOAuthToken(uuid.toString())).thenReturn(response);
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())
                        .param("refresh_token", uuid.toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").value(response.getAccessToken()))
                .andExpect(jsonPath("$.refresh_token").value(response.getRefreshToken())));
    }

    @Test
    void oauthTokenEndpointWithInvalidRequest_thenBadRequest() {
        var expectedErrorCode = "invalid_request";
        // no fields
        assertDoesNotThrow(
                () -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
                        .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // only non supported parameters
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("invalid_parameter", ""))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing required fields
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("refresh_token", ""))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter preauth code
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName()))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName()))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpointWithInvalidGrant_thenBadRequest() {
        var expectedErrorCode = "invalid_grant";
        var code = "invalid code";
        var token = "invalid token";

        // tests if the error is propagated properly. Test for correct error being
        // thrown is in OAuthServiceTest
        when(oAuthService.issueOAuthToken(code)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("pre-authorized_code", code)
                        .param("grant_type", OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName()))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // tests if the error is propagated properly. Test for correct error being
        // thrown is in OAuthServiceTest
        when(oAuthService.refreshOAuthToken(token)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName()).param("refresh_token", token))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpointWithUnsupportedGrantType_thenBadRequest() {
        var expectedErrorCode = "unsupported_grant_type";
        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "invalid grant type")
                        .param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        assertDoesNotThrow(() -> mvc
                .perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "").param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void testCredentialEndpoint_whenMalformedRequest() {

        var ex = assertThrows(Oid4vcException.class,
                () -> controller.createCredential(ACCESS_TOKEN, null, "Hello world", httpRequest));
        assertThat(ex.getError()).as(INVALID_REQUEST_REASON)
                .isEqualTo(CredentialRequestError.INVALID_CREDENTIAL_REQUEST);
    }

    @Test
    void testDeferredEndpoint_whenMalformedRequest() {
        var ex = assertThrows(Oid4vcException.class,
                () -> controller.createDeferredCredential(ACCESS_TOKEN, null, "Hello World", httpRequest));
        assertThat(ex.getError()).as(INVALID_REQUEST_REASON)
                .isEqualTo(CredentialRequestError.INVALID_CREDENTIAL_REQUEST);
    }
    private final String credentialEndpoint = "/oid4vci/api/credential";

    @Test
    void createCredential_invalidAccessToken_thenError() {
        var accessToken = "Bearer foo";
        var errorDescription = "example description";
        when(oAuthService.getAccessToken(accessToken)).thenThrow(OAuthException.invalidRequest(errorDescription));
        assertDoesNotThrow(() -> mvc.perform(
                                post(credentialEndpoint).contentType("application/jwt").content("{}")
                                        .header("Authorization", accessToken)
                        ).andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.error").value("invalid_credential_request"))
                        .andExpect(jsonPath("$.error_description").value(errorDescription))

        );
    }
}
