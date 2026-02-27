package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthAuthorizationServerMetadataDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.credential.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementService;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
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
    private final String externalUrl = "http://localhost:8080";
    private final String issuerId = "did:example:issuer";

    private OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private CredentialManagementService credentialManagementService;
    private JwsSignatureFacade jwsSignatureFacade;
    private SdjwtProperties sdjwtProperties;
    private JweService jweService;
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private MetadataService metadataService;
    private ConfigurationOverride override;
    private ApplicationProperties applicationProperties;
    private IssuerMetadata defaultTestIssuerMetadata;

    @BeforeEach
    void setUp() {
        openIdIssuerConfiguration = mock(OpenIdIssuerConfiguration.class);
        credentialManagementService = mock(CredentialManagementService.class);
        jwsSignatureFacade = mock(JwsSignatureFacade.class);
        sdjwtProperties = mock(SdjwtProperties.class);
        applicationProperties = mock(ApplicationProperties.class);
        jweService = mock(JweService.class);
        demonstratingProofOfPossessionService = mock(DemonstratingProofOfPossessionService.class);

        defaultTestIssuerMetadata = IssuerMetadata.builder()
                .credentialIssuer(externalUrl)
                .profileVersion(SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .build();
        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(defaultTestIssuerMetadata);

        // ObjectMapper not needed for tested methods here
        metadataService = new MetadataService(openIdIssuerConfiguration, credentialManagementService, jwsSignatureFacade, jweService, demonstratingProofOfPossessionService, sdjwtProperties, applicationProperties, new ObjectMapper());

        override = new ConfigurationOverride(null, null, null, null);
        when(applicationProperties.getIssuerId()).thenReturn(issuerId);
        when(applicationProperties.getExternalUrl()).thenReturn(externalUrl);
    }

    @Test
    void getUnsignedIssuerMetadata_returnsMap() {
        IssuerMetadata result = metadataService.getUnsignedIssuerMetadata();

        assertNotNull(result);
        assertEquals(defaultTestIssuerMetadata, result);
    }

    @Test
    void getSignedIssuerMetadata_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = createDummySigner();

        when(jwsSignatureFacade.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

        String jwtStr = metadataService.getSignedIssuerMetadata(tenantId);
        assertNotNull(jwtStr);

        SignedJWT parsed = SignedJWT.parse(jwtStr);
        assertEquals(issuerId, parsed.getJWTClaimsSet().getIssuer());
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onKeyStrategyError() throws KeyStrategyException {
        UUID tenantId = UUID.randomUUID();
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);
        when(jwsSignatureFacade.createSigner(sdjwtProperties, null, null)).thenThrow(new KeyStrategyException("bad", null));

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedIssuerMetadata_throwsConfigurationException_onJoseException() throws Exception {
        UUID tenantId = UUID.randomUUID();

        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(IssuerMetadata.builder().build());
        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        JWSSigner signer = mock(JWSSigner.class);
        when(signer.sign(any(), any())).thenThrow(new JOSEException("bad"));
        when(jwsSignatureFacade.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

        assertThrows(ConfigurationException.class, () -> metadataService.getSignedIssuerMetadata(tenantId));
    }

    @Test
    void getSignedOAuthAuthorizationServerMetadata_successfulSigning_returnsJwt() throws Exception {
        UUID tenantId = UUID.randomUUID();
        var oidConfig = new OAuthAuthorizationServerMetadataDto(externalUrl, "token_endpoint", null, null);
        when(demonstratingProofOfPossessionService.addSigningAlgorithmsSupportedAndSwissprofileVersion(Mockito.any())).thenReturn(oidConfig);
        when(metadataService.getUnsignedOAuthAuthorizationServerMetadata()).thenReturn(oidConfig);


        when(credentialManagementService.getConfigurationOverrideByTenantId(tenantId)).thenReturn(override);

        MetadataService svc = new MetadataService(openIdIssuerConfiguration, credentialManagementService, jwsSignatureFacade, jweService, demonstratingProofOfPossessionService, sdjwtProperties, applicationProperties, new ObjectMapper());

        JWSSigner signer = createDummySigner();
        when(jwsSignatureFacade.createSigner(sdjwtProperties, null, null)).thenReturn(signer);

        String jwt = svc.getSignedOAuthAuthorizationServerMetadata(tenantId);
        assertNotNull(jwt);
        SignedJWT parsed = SignedJWT.parse(jwt);
        // Constructing the expected tenant's credential issuer identifier
        String credentialIssuerIdentifier = String.format("%s/%s", externalUrl, tenantId);
        assertEquals(credentialIssuerIdentifier, parsed.getJWTClaimsSet().getSubject(), "Subject claim must be the credential issuer identifier");
        assertEquals(credentialIssuerIdentifier, parsed.getJWTClaimsSet().getStringClaim("issuer"), "Issuer claim must be the credential issuer identifier");
        assertEquals("token_endpoint", parsed.getJWTClaimsSet().getStringClaim("token_endpoint"));
    }

    private JWSSigner createDummySigner() throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        return new ECDSASigner(ecJWK);
    }
}