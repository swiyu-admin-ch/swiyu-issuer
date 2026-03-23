package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenGrantType;
import ch.admin.bj.swiyu.issuer.infrastructure.web.signer.IssuanceController;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = IssuanceController.class)
@ActiveProfiles("test")
//@AutoConfigureMockMvc(addFilters = false)
@RunWith(SpringRunner.class)
class IssuanceControllerTest {
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

    @MockitoBean
    private DemonstratingProofOfPossessionService dpopService;
    @Autowired
    private MockMvc mvc;

    org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper objectMapper = new org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper();

    // https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2


    @Test
    void oauthTokenEndpoint_invalidRequest() {
        var expectedErrorCode = "invalid_request";
        // all fields empty
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("invalid_parameter", "")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing required fields
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("refresh_token", "")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter preauth code
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    void oauthTokenEndpoint_invalidClient() {
        // TODO@MP
        var expectedErrorCode = "invalid_client";

        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "")
                        .param("pre-authorized_code", "")
                        .param("refresh_token", "")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpoint_invalidGrant() {
        var expectedErrorCode = "invalid_grant";
        var code = "invalid code";
        var token = "invalid token";

        // tests if the error is propagated properly. Test for correct error being thrown is in OAuthServiceTest
        when(oAuthService.issueOAuthToken(code)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("pre-authorized_code", code)
                        .param("grant_type", OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName())
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // tests if the error is propagated properly. Test for correct error being thrown is in OAuthServiceTest
        when(oAuthService.refreshOAuthToken(token)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())
                        .param("refresh_token", token)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpoint_unsupportedGrantType() {
        var expectedErrorCode = "unsupported_grant_type";
        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token").with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "invalid grant type")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));

        assertDoesNotThrow(() -> mvc.perform(post("/oid4vci/api/token").with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

}
