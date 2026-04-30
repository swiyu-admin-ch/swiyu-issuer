package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.infrastructure.web.signer.IssuanceController;
import ch.admin.bj.swiyu.issuer.service.AuthorizationService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.CredentialServiceOrchestrator;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.ObjectMapper;


import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class IssuanceControllerTest {
    private static final String ACCESS_TOKEN = "00000000-0000-0000-0000-000000000000";

    private CredentialServiceOrchestrator credentialServiceOrchestrator;
    private JweService jweService;
    private OAuthService oAuthService;

    // Relevant mocks for the tests in this class
    private HttpServletRequest httpRequest;
    private AuthorizationService authorizationService;
    private IssuanceController controller;

    private ObjectMapper objectMapper = new ObjectMapper();

    private static final String INVALID_REQUEST_REASON = "When the Credential Request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed, the error 'invalid_credential_request' must be returned.";

    @BeforeEach
    void setup() {
        credentialServiceOrchestrator = Mockito.mock(CredentialServiceOrchestrator.class);
        jweService = Mockito.mock(JweService.class);
        oAuthService = Mockito.mock(OAuthService.class);
        httpRequest = Mockito.mock(HttpServletRequest.class);
        authorizationService = Mockito.mock(AuthorizationService.class);
        controller = new IssuanceController(credentialServiceOrchestrator, jweService, null, objectMapper, authorizationService);

        when(jweService.decryptRequest(anyString(), anyString())).then(a -> {
            return a.getArguments()[0];
        }); // Return input
        when(oAuthService.getAccessToken(anyString())).thenReturn(ACCESS_TOKEN);
        when(httpRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(httpRequest.getContentType()).thenReturn("application/json");
        when(httpRequest.getAttribute(anyString())).thenReturn("Test");
        when(authorizationService.processOAuthTokenEndpointRequest(any(), any(), any())).thenCallRealMethod();
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

    @Test
    void createCredential_invalidAccessToken_thenError() {
        when(authorizationService.getValidatedAccessToken(ACCESS_TOKEN, null, httpRequest))
                .thenThrow(OAuthException.invalidToken("Invalid Token"));

        var ex = assertThrows(OAuthException.class,
                () -> controller.createCredential(ACCESS_TOKEN, null, "Hello World", httpRequest));
        assertThat(ex.getError()).as(INVALID_REQUEST_REASON)
                .isEqualTo(OAuthError.INVALID_TOKEN);
    }
}