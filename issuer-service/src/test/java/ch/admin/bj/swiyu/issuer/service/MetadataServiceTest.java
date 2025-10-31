package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
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
import org.mockito.Mockito;

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
    private EncryptionService encryptionService;
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private MetadataService metadataService;
    private ConfigurationOverride override;
    private ApplicationProperties applicationProperties;

    @BeforeEach
    void setUp() {
        openIdIssuerConfiguration = mock(OpenIdIssuerConfiguration.class);
        credentialManagementService = mock(CredentialManagementService.class);
        signatureService = mock(SignatureService.class);
        sdjwtProperties = mock(SdjwtProperties.class);
        applicationProperties = mock(ApplicationProperties.class);
        encryptionService = mock(EncryptionService.class);
        demonstratingProofOfPossessionService = mock(DemonstratingProofOfPossessionService.class);

        // ObjectMapper not needed for tested methods here
        metadataService = new MetadataService(openIdIssuerConfiguration, credentialManagementService, signatureService, encryptionService, demonstratingProofOfPossessionService, sdjwtProperties, applicationProperties, new ObjectMapper());

        override = new ConfigurationOverride(null, null, null, null);
        when(applicationProperties.getIssuerId()).thenReturn("did:example:issuer");
    }

    @Test
    void getUnsignedIssuerMetadata_returnsMap() {
        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setVersion("1.0.0");
        when(encryptionService.issuerMetadataWithEncryptionOptions()).thenReturn(metadata);

        IssuerMetadata result = metadataService.getUnsignedIssuerMetadata();

        assertNotNull(result);
        assertEquals(metadata, result);
    }

    @Test
    void getSignedIssuerMetadata_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setVersion("1.0.0");
        when(encryptionService.issuerMetadataWithEncryptionOptions()).thenReturn(metadata);
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = createDummySigner();

        when(signatureService.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

        String jwtStr = metadataService.getSignedIssuerMetadata(tenantId);
        assertNotNull(jwtStr);

        SignedJWT parsed = SignedJWT.parse(jwtStr);
        assertEquals("did:example:issuer", parsed.getJWTClaimsSet().getSubject());
        assertEquals("1.0.0", parsed.getJWTClaimsSet().getStringClaim("version"));
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onKeyStrategyError() throws KeyStrategyException {
        UUID tenantId = UUID.randomUUID();
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);
        when(signatureService.createSigner(sdjwtProperties, null, null)).thenThrow(new KeyStrategyException("bad", null));

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onJoseException() throws Exception {
        UUID tenantId = UUID.randomUUID();

        when(encryptionService.issuerMetadataWithEncryptionOptions()).thenReturn(new IssuerMetadata());
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = mock(JWSSigner.class);
        when(signer.sign(any(), any())).thenThrow(new JOSEException("bad"));
        when(signatureService.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedOpenIdConfiguration_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        var oidConfig = new OpenIdConfigurationDto("issuer", "token_endpoint", null);
        when(demonstratingProofOfPossessionService.addSigningAlgorithmsSupported(Mockito.any())).thenReturn(oidConfig);

        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        MetadataService svc = new MetadataService(openIdIssuerConfiguration, credentialManagementService, signatureService, encryptionService, demonstratingProofOfPossessionService, sdjwtProperties, applicationProperties, new ObjectMapper());

        JWSSigner signer = createDummySigner();
        when(signatureService.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

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