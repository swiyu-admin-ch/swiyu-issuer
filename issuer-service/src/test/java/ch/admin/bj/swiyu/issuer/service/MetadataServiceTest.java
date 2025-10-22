package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MetadataServiceTest {

    private OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private CredentialManagementService credentialManagementService;
    private SignatureService signatureService;
    private SdjwtProperties sdjwtProperties;
    private MetadataService metadataService;
    private ConfigurationOverride override;
    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        openIdIssuerConfiguration = mock(OpenIdIssuerConfiguration.class);
        credentialManagementService = mock(CredentialManagementService.class);
        signatureService = mock(SignatureService.class);
        sdjwtProperties = mock(SdjwtProperties.class);

        // ObjectMapper not needed for tested methods here
        metadataService = new MetadataService(openIdIssuerConfiguration, credentialManagementService, signatureService, sdjwtProperties);

        override = mock(ConfigurationOverride.class);
        when(override.keyId()).thenReturn("kid");
        when(override.keyPin()).thenReturn("pin");
        when(override.issuerDid()).thenReturn("did:example:issuer");
    }

    @Test
    void getUnsignedIssuerMetadata_returnsMap() throws IOException {
        Map<String, Object> meta = new HashMap<>();
        meta.put("foo", "bar");
        when(openIdIssuerConfiguration.getIssuerMetadata()).thenReturn(meta);

        Map<String, Object> result = metadataService.getUnsignedIssuerMetadata();

        assertNotNull(result);
        assertEquals("bar", result.get("foo"));
    }

    @Test
    void getUnsignedIssuerMetadata_throwsConfigurationException_onIo() throws IOException {
        when(openIdIssuerConfiguration.getIssuerMetadata()).thenThrow(new IOException("bad"));

        assertThrows(ConfigurationException.class, () -> metadataService.getUnsignedIssuerMetadata());
    }

    @Test
    void getSignedIssuerMetadata_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Map<String, Object> meta = Map.of("a", "b");

        when(openIdIssuerConfiguration.getIssuerMetadata()).thenReturn(meta);
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = createDummySigner();

        when(signatureService.createSigner(sdjwtProperties, "kid", "pin")).thenReturn(signer);

        String jwtStr = metadataService.getSignedIssuerMetadata(tenantId);
        assertNotNull(jwtStr);

        SignedJWT parsed = SignedJWT.parse(jwtStr);
        assertEquals("did:example:issuer", parsed.getJWTClaimsSet().getSubject());
        assertEquals("b", parsed.getJWTClaimsSet().getStringClaim("a"));
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onKeyStrategyError() throws KeyStrategyException {
        UUID tenantId = UUID.randomUUID();
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);
        when(signatureService.createSigner(sdjwtProperties, "kid", "pin")).thenThrow(new KeyStrategyException("bad", null));

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onJoseException() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Map<String, Object> meta = Map.of("x", "y");

        when(openIdIssuerConfiguration.getIssuerMetadata()).thenReturn(meta);
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = mock(JWSSigner.class);
        when(signer.sign(any(), any())).thenThrow(new JOSEException("bad"));
        when(signatureService.createSigner(sdjwtProperties, "kid", "pin")).thenReturn(signer);

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedOpenIdConfiguration_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Map<String, Object> map = Map.of("issuer", "issuer", "token_endpoint", "token_endpoint");

        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);
        when(openIdIssuerConfiguration.getOpenIdConfiguration()).thenReturn(map);

        MetadataService svc = new MetadataService(openIdIssuerConfiguration, credentialManagementService, signatureService, sdjwtProperties);

        JWSSigner signer = createDummySigner();
        when(signatureService.createSigner(sdjwtProperties, "kid", "pin")).thenReturn(signer);

        String jwt = svc.getSignedOpenIdConfiguration(tenantId);
        assertNotNull(jwt);
        SignedJWT parsed = SignedJWT.parse(jwt);
        assertEquals("did:example:issuer", parsed.getJWTClaimsSet().getSubject());
        assertEquals("issuer", parsed.getJWTClaimsSet().getStringClaim("issuer"));
        assertEquals("token_endpoint", parsed.getJWTClaimsSet().getStringClaim("token_endpoint"));
    }

    private JWSSigner createDummySigner() throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        return new ECDSASigner(ecJWK);
    }
}