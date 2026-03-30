package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenGrantType;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenTypeDto;
import ch.admin.bj.swiyu.issuer.infrastructure.web.signer.IssuanceController;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = IssuanceController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class IssuanceControllerTest {
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
    @Autowired
    private MockMvc mvc;

    private final String tokenEndpoint = "/oid4vci/api/token";

    @Test
    void oauthTokenEndpointWithValidPreAuthorizedCode_thenSuccess() {
        var uuid = UUID.randomUUID();
        var response = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh").tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.issueOAuthToken(uuid.toString())).thenReturn(response);
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName()).param("pre-authorized_code", uuid.toString())).andExpect(status().isOk()).andExpect(jsonPath("$.access_token").value(response.getAccessToken())).andExpect(jsonPath("$.refresh_token").value(response.getRefreshToken())));
    }

    @Test
    void oauthTokenEndpointWithValidRefreshToken_thenSuccess() {
        var uuid = UUID.randomUUID();
        var response = OAuthTokenDto.builder().accessToken("access").refreshToken("refresh").tokenType(OAuthTokenTypeDto.BEARER).build();
        when(oAuthService.refreshOAuthToken(uuid.toString())).thenReturn(response);
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName()).param("refresh_token", uuid.toString())).andExpect(status().isOk()).andExpect(jsonPath("$.access_token").value(response.getAccessToken())).andExpect(jsonPath("$.refresh_token").value(response.getRefreshToken())));
    }

    @Test
    void oauthTokenEndpointWithInvalidRequest_thenBadRequest() {
        var expectedErrorCode = "invalid_request";
        // no fields
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // only non supported parameters
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("invalid_parameter", "")).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing required fields
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("refresh_token", "")).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter preauth code
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // missing parameter
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName())).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpointWithInvalidGrant_thenBadRequest() {
        var expectedErrorCode = "invalid_grant";
        var code = "invalid code";
        var token = "invalid token";

        // tests if the error is propagated properly. Test for correct error being thrown is in OAuthServiceTest
        when(oAuthService.issueOAuthToken(code)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("pre-authorized_code", code).param("grant_type", OAuthTokenGrantType.PRE_AUTHORIZED_CODE.getName())).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        // tests if the error is propagated properly. Test for correct error being thrown is in OAuthServiceTest
        when(oAuthService.refreshOAuthToken(token)).thenThrow(OAuthException.invalidToken("invalid token"));
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", OAuthTokenGrantType.REFRESH_TOKEN.getName()).param("refresh_token", token)).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    @Test
    void oauthTokenEndpointWithUnsupportedGrantType_thenBadRequest() {
        var expectedErrorCode = "unsupported_grant_type";
        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", "invalid grant type").param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef")).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));

        assertDoesNotThrow(() -> mvc.perform(post(tokenEndpoint).contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE).param("grant_type", "").param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef")).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value(expectedErrorCode)));
    }

    private final String credentialEndpoint = "/oid4vci/api/credential";

    @Test
    void createCredential_invalidPayload_thenError() {
        var payload = "invalid json payload";
        var encryptedPayload = "eyJ6aXAiOiJERUYiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI5cDdNdHdvekZOQ2ZHb0VPN0UzVE9iT3ltUzBDSUhVNXpMS3E3MDhuUElnIiwieSI6Inl2a19nNVo1eGpQeS10cDAybkNQQWFYOW9OeDV6M1h2YURrbDQtTm1ZWG8ifSwia2lkIjoiZTdkN2FmNzgtZDZiNi00NjZhLWEzNTUtNzk1YjZkMmFjZDE2IiwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IkVDREgtRVMifQ..oOciMWChd0EuW0H1.zB-_tbdTdBYnh5MWVui15xRAuhL9VvMN78PW7hd42CerI3M-c_WFncM0_f8-mSBQUFgsYD6RgKtmCDwgI4iOW2gtlS4lyIeCZb-2hbNZADrvPWZO_Qy89oGWBzv82LhqDJyBK_hhahP-H48pbcjnTttbElJS0XdGOxnIraM0rF-Ubwh5OR9Rft1sPBUXok-G52HsVnwv9X9CKn4ElJeK6ruVT08i9yS1sIVZEtARi0haxBu1MpqrEWmIoTvoK-Sl1GUu1pEVCqZJekRk9-jHAZslEEtEC-q5kgDo1uAGqvmcb4tuT3D82ZkqjPT4--CGgafwgiPF3V1yZO4983oyYe9xC5C-xC1D9w7YrfCtI4uAyf7G7dK0jTlti73J16cgboFc7Bj3pQ8k3Zd0IXw8sDGFFRcVgtN6rYnFEnPcAi7xQA6y2EW3HT4ooN_QRl3UnAnSj1tvk4CNVOt6c0mWToncqFpgPZ5Odu3q9YDb50D-MhzDczyGDiwVIkkzNBpqot905tdsV_iJ6E7AJgRiz52W6q9vb2hBrCJTxdafCBeYV31ZU7kFnoIRYY-1QwYuk4zGJ3-0C6QvK_CEyWenCf4V_fXta19Q-rGtIdMw_sUGC15j2tKeCRC--DWdYqlYKTCMAVPGA7Ndbdq1iYTrasG7OXSBoNTksN2YzfKaJy8gYWlutWV6AOB1HdLBMJnH0pnL4H5Ptz3X4P0PM9rp4C4PAwjMHDZP5Q0wJDtZJCAsrJbPBoHVuJaD8htxOE8MgW7VzkkizFfigAv5jX1Jt0ZEjaIlAhR1N2aE8m3CcSV5MmwDRy3C38-fTPQe6_m7V6pQzYhdhPTjnc4K2E5_VCb4pB1-ZlJTX-5INIkffWDXtSamWBjqpxOEW6qtrcb9w6VCbf7beUkThIbHWm4pqTYI3iVMEP3pz_VMkfh5KsYe7sT5UAPM5Dns2tSPNJGXhCbxbP1dgILnViqzj_akhR1rLpta0NtvADPAaDCL495vOXXtcj3v24V1n2ZjWALQepk8iM1uQPfBbQ_Hc5Tv3xfGjWAN950_rY7U7_DRMri8-DwQvZblnOR_DdTprBKx9JEN7UaW0yXtxtdJIUxefmxpdTf1SXCLETm-ZjLLiCwOBP4viHYF1emBlIVirk-ALfaiJAqQq34vNvS4FeATGzNSk2XnKc4KoStKqNkqTlL1J95taakW0MAmE1ldULVSRYVxbXv6T1XxGTmcLTwN2ZWIrimZMClCcDFq0aSEj4hzeoGWmYVoMI1Hxf-xTH0w-F0TpBg9fkqjY-7sYrjXkUDg0Mj3wfsrVKksra0O1ZZztFYAvB3VUrPvdaibAoFaytLLV_tlDd5StjjJHJ9k3aH1dVOUHJGZNGEkYZlIvUBnaZkJbxgLrNEFUctjNu3Ms9jP7zrj7b4L6vx4f8X5WBpVGN77RCUxkg0Dxf2MzWthiIPWyfA3hcszyQzpPN134AnYRHRT0XtMltSvppTYWTxOmy2II2EwvbPXilwcGSsLPQdRJdOVZVGOrD7mO7rvL9kltz-hv8r0Jr5ipYC5-KW58mj8iQC2t45uzPOXDrdNKcL4t-dfuMxL_gaAGAP4LKP_NP8sNBlZw_UzZLFq2ioNwjDT1Rsf2qBOHHypYbhkrUB9oz3-C3x35yhJ8fInK9YRXr1BEg6OvWWwNxqVZ_GJfiwYaWpJ0nvvS4RuQTYBBJNYQICqr1b6QK7Hyu7ThLgDzxOtjNgTAHWg_Yl1AmS1_SWaflqH1YxmQd-K8kYI_ZMF93Veej5ic2nG_Obxkrloz1sKYXXLNM9s93JeHGNX_NxV5YHggsRbq37KAyvLyfUxxDyGq8mGPSl2a49KuNv5jXQW3TWt8US-OFKkyPhhOEHRxzu6ShAgnPNfJOyh_ku2UJRdU6Ks8NTGO3ZKjiaX4lvRSQVa_GNk-hspulTvGBOaQuBj1AWb7us7fBLrlpdBIKfw8lb_FE0EtTIPILg2iTWHvIv2qDHOa8BD-CPKjmwsnDxzAjP0YxC8r9hFpLFR4bU1xhiR3p0NAzVKgr4GgpvWN8gbANzNvCNf7xLDaMRpX5IRmLrL8w3x1epGcOFDR_lc6zMGYGJZJPc0prTjHEKjOwtQBLczO2BJGbANHUg-3RUk_krsMTctWazcQIgZqUNpsVvSeDOuvd1_GHXKAR_CuqdPN16Z62omn6iETU4683aNdBROldMF6eTsEq2z5rPgALEBdO0u4F8oyATwJpJve9TigB5s4FGDzI2AHSCWj6rPWj6Os_W42u70a08zb_NQRCclJ2wnkmi9SrRaVQaEqG_JB9a0U0MSnAfshEANxMy6lqUMip9bBxuvEG4tS7jyzBes3p_qFi3ukCpnNgUfpTvK37CiHu8Pkaz9lTrPdRVkyCcBrZc820SxWaePUe3He-Y--WOYUHVQjHVBhJPLPUiO-LOGhgAsoWnTYVd70NuB7LXUEgKXvAXyuuCAjagMSidvTXOlVIy4OcJLfrd9A8VgxC_qMhvsMXuq3fUYRetDRqirq0okF5SGEjSew8ZvSTP5Pixf2n-GXVOnHDoiiApTOzizWGjfKKbpy3tb_y244BbMilQcMlzp6Gi2VZ7PAUL8QBgl9riuMZKwIeGi7qn9wd2xd8H34ywkO9oJXBS4eKv7XpnG3ANoZ1PT-VnPclIhqMDzPa9LWOM6rE0kxRpDJief_o59Q3Udi2foGi8u-ZCXXFh62Hx4YJZjDJ1JSfJLl1xxgO9IMOV8hB1dUT_g6rzVO8179vwZOJOoh9Jlm_8FIuYzRMLKqoAUbzW9bDsNqfWN87aoug9S2c9qKolBQMyMfa13do_Kcz3wTp78Mw8v32OMZZgHEJ4LU9oZMT1FifQ_2HfqpcRbuTGNuW416q4rbOENqg.DVOplSKM3tKsWy7cPBDlGQ\n";
        var accessToken = "accessToken";
        when(oAuthService.getAccessToken(any())).thenReturn(accessToken);
        // decryptRequest only decrypts the request when content-type is set to application/jwt, otherwise the payload is returned as is.
        when(jweService.decryptRequest(encryptedPayload, MediaType.APPLICATION_JSON_VALUE)).thenReturn(encryptedPayload);
        when(jweService.decryptRequest(payload, MediaType.APPLICATION_JSON_VALUE)).thenReturn(payload);

        // invalid json body
        assertDoesNotThrow(() -> mvc.perform(
                post(credentialEndpoint).contentType(MediaType.APPLICATION_JSON_VALUE).content(encryptedPayload)
                        .header("Authorization", "Bearer FOO")
        ).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_request")));

        // encrypted content, but incorrect header
        assertDoesNotThrow(() -> mvc.perform(
                post(credentialEndpoint).contentType(MediaType.APPLICATION_JSON_VALUE).content(encryptedPayload)
                        .header("Authorization", "Bearer FOO")
        ).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_request")));
    }

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
