package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.ObjectMapper;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.infrastructure.web.signer.IssuanceController;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Validator;

class IssuanceControllerTest {
    private static final String ACCESS_TOKEN = "00000000-0000-0000-0000-000000000000";
    private IssuanceController controller;
    private HttpServletRequest httpRequest;
    private JweService jweService;

    private static final String INVALID_REQUEST_REASON = "When the Credential Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed, the error 'invalid_credential_request' must be returned.";

    @BeforeEach
    void setup() {
        var orchestrator = Mockito.mock(CredentialServiceOrchestrator.class);
        var nonceService = Mockito.mock(NonceService.class);
        var oauthService = Mockito.mock(OAuthService.class);
        jweService = Mockito.mock(JweService.class);
        when(jweService.decryptRequest(anyString(), anyString())).then(a -> {
            return a.getArguments()[0];
        }); // Return input
        Mockito.when(oauthService.getAccessToken(anyString())).thenReturn(ACCESS_TOKEN);
        var dpopService = Mockito.mock(DemonstratingProofOfPossessionService.class);
        var validator = Mockito.mock(Validator.class);
        var objectMapper = new ObjectMapper();
        controller = new IssuanceController(orchestrator, nonceService, jweService, oauthService, dpopService,
                validator, objectMapper);
        httpRequest = Mockito.mock(HttpServletRequest.class);
        when(httpRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpRequest.getContentType()).thenReturn("application/json");
        when(httpRequest.getAttribute(anyString())).thenReturn("Test");
    }


    @Test
    void testCredentialEndpoint_whenMalformedRequest() {
        var ex = assertThrows(Oid4vcException.class,
                () -> controller.createCredential(ACCESS_TOKEN, null, "Hello world", httpRequest));
        assertThat(ex.getError()).as(INVALID_REQUEST_REASON).isEqualTo(CredentialRequestError.INVALID_CREDENTIAL_REQUEST);
    }

    @Test 
    void testDeferredEndpoint_whenMalformedRequest() {
        var ex = assertThrows(Oid4vcException.class, () -> controller.createDeferredCredential(ACCESS_TOKEN, null, "Hello World", httpRequest));
        assertThat(ex.getError()).as(INVALID_REQUEST_REASON).isEqualTo(CredentialRequestError.INVALID_CREDENTIAL_REQUEST);
    }
}
