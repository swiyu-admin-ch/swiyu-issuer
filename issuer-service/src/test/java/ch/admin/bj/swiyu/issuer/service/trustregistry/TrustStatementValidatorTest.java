package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import ch.admin.eid.did_sidekicks.DidDoc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class TrustStatementValidatorTest {

    private DidJwtValidator trustStatementDidJwtValidator;
    private DidResolverAdapter didResolverAdapter;
    private UrlRewriteProperties urlRewriteProperties;
    private TrustStatementValidator validator;

    @BeforeEach
    void setUp() {
        trustStatementDidJwtValidator = mock(DidJwtValidator.class);
        didResolverAdapter = mock(DidResolverAdapter.class);
        urlRewriteProperties = mock(UrlRewriteProperties.class);

        when(urlRewriteProperties.getUrlMappings()).thenReturn(Map.of());

        validator = new TrustStatementValidator(
                trustStatementDidJwtValidator,
                didResolverAdapter,
                urlRewriteProperties
        );
    }

    @Test
    void validateAllowlist_passesWhenUnderlyingValidatorPasses() {
        String jwt = "dummy.jwt.string";
        when(trustStatementDidJwtValidator.getAndValidateResolutionUrl(jwt)).thenReturn("https://trust-registry.example.com");
        when(trustStatementDidJwtValidator.getDidString(jwt)).thenReturn("did:tdw:trust-registry.example.com");

        validator.validateAllowlist(jwt);

        verify(trustStatementDidJwtValidator, times(1)).getAndValidateResolutionUrl(jwt);
        verify(trustStatementDidJwtValidator, times(1)).getDidString(jwt);
    }

    @Test
    void validateAllowlist_throwsWhenUnderlyingValidatorThrows() {
        String jwt = "dummy.jwt.string";
        when(trustStatementDidJwtValidator.getAndValidateResolutionUrl(jwt))
                .thenThrow(new JwtValidatorException("Validation failed"));

        assertThatThrownBy(() -> validator.validateAllowlist(jwt))
                .isInstanceOf(JwtValidatorException.class)
                .hasMessage("Validation failed");
    }

    @Test
    void validateSignature_fetchesDidDocAndValidates() {
        String jwt = "dummy.jwt.string";
        String did = "did:tdw:trust-registry.example.com";
        DidDoc didDoc = mock(DidDoc.class);

        when(trustStatementDidJwtValidator.getDidString(jwt)).thenReturn(did);
        when(didResolverAdapter.resolveDid(eq(did), anyMap())).thenReturn(didDoc);

        validator.validateSignature(jwt);

        verify(didResolverAdapter, times(1)).resolveDid(eq(did), anyMap());
        verify(trustStatementDidJwtValidator, times(1)).validateJwt(jwt, didDoc);
    }

    @Test
    void validateSignature_throwsWhenDidResolutionFails() {
        String jwt = "dummy.jwt.string";
        String did = "did:tdw:trust-registry.example.com";

        when(trustStatementDidJwtValidator.getDidString(jwt)).thenReturn(did);
        when(didResolverAdapter.resolveDid(eq(did), anyMap()))
                .thenThrow(new RuntimeException("DID resolution failed"));

        assertThatThrownBy(() -> validator.validateSignature(jwt))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("DID resolution failed");
    }

    @Test
    void validateSignature_throwsWhenSignatureIsInvalid() {
        String jwt = "dummy.jwt.string";
        String did = "did:tdw:trust-registry.example.com";
        DidDoc didDoc = mock(DidDoc.class);

        when(trustStatementDidJwtValidator.getDidString(jwt)).thenReturn(did);
        when(didResolverAdapter.resolveDid(eq(did), anyMap())).thenReturn(didDoc);
        doThrow(new JwtValidatorException("Invalid signature"))
                .when(trustStatementDidJwtValidator).validateJwt(jwt, didDoc);

        assertThatThrownBy(() -> validator.validateSignature(jwt))
                .isInstanceOf(JwtValidatorException.class)
                .hasMessage("Invalid signature");
    }
}

