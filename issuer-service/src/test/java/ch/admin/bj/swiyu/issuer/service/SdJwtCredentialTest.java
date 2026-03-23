package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.HolderKeyBinding;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SdJwtCredentialTest {

    private final String metadataCredentialSupportedId = "metadata-supported";
    private ApplicationProperties applicationProperties;
    private IssuerMetadata issuerMetadata;
    private DataIntegrityService dataIntegrityService;
    private SdjwtProperties sdjwtProperties;
    private JwsSignatureFacade jwsSignatureFacade;
    private StatusListRepository statusListRepository;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    private CredentialConfiguration credentialConfiguration;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        issuerMetadata = mock(IssuerMetadata.class);
        dataIntegrityService = mock(DataIntegrityService.class);
        sdjwtProperties = mock(SdjwtProperties.class);
        jwsSignatureFacade = mock(JwsSignatureFacade.class);
        statusListRepository = mock(StatusListRepository.class);
        credentialOfferStatusRepository = mock(CredentialOfferStatusRepository.class);

        credentialConfiguration = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.getIssuerId()).thenReturn("did:example:issuer");
    }

    private JWSSigner createTestSigner() throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("test-key")
                .generate();
        return new ECDSASigner(ecJWK);
    }

    @Test
    void shouldIssueSingleSdJwtAndStoreVcHash_whenVcHashStorageEnabled() throws Exception {

        var configurationId = "metadata-supported";
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, config));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(config);

        CredentialOffer offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(configurationId))
                .offerData(Map.of("foo", "bar"))
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(configurationId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // Assert
        assertNotNull(credentials);
        assertEquals(1, credentials.size());

        assertNotNull(offer.getVcHashes());
        assertEquals(1, offer.getVcHashes().size());
    }

    @Test
    void shouldThrowWhenStatusReferencesIncompatibleWithBatchSize() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));

        CredentialOffer offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(metadataCredentialSupportedId))
                .offerData(Map.of())
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        // prepare 1 status references
        var statusListId = UUID.randomUUID();
        var key = new CredentialOfferStatusKey(offer.getId(), statusListId, 1);
        var status = CredentialOfferStatus.builder().id(key).build();
        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of(status));

        // status list referenced
        StatusList sl = StatusList.builder().id(statusListId).uri("https://example.com/status/1").build();
        when(statusListRepository.findById(statusListId)).thenReturn(Optional.of(sl));

        // issuer metadata allows batch issuance
        when(issuerMetadata.isBatchIssuanceAllowed()).thenReturn(true);
        when(issuerMetadata.getIssuanceBatchSize()).thenReturn(10);

        var subject = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        JWSSigner signer = createTestSigner();
        doReturn(signer).when(subject).createSigner();

        subject.credentialOffer(offer);

        // provide two holder keys so batch size becomes 2
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        HolderKeyBinding holderKeyBinding1 = HolderKeyBinding.createFromJsonString(ecJWK.toPublicJWK().toJSONString());
        ECKey ecJWK2 = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        HolderKeyBinding holderKeyBinding2 = HolderKeyBinding.createFromJsonString(ecJWK2.toPublicJWK().toJSONString());

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> subject.getCredential(List.of(holderKeyBinding1, holderKeyBinding2)));
    }

    @Test
    void shouldNotOverrideProtectedClaimsFromOfferData() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(metadataCredentialSupportedId)).thenReturn(credentialConfiguration);

        CredentialOffer offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(metadataCredentialSupportedId))
                .offerData(Map.of("vct", "malicious", "name", "Alice"))
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        // Act
        List<String> creds = sdJwtCredential.getCredential(null);
        assertEquals(1, creds.size());

        String sdjwt = creds.getFirst();
        String signedJwtPart = sdjwt.contains("~") ? sdjwt.split("~")[0] : sdjwt;
        var parsed = com.nimbusds.jwt.SignedJWT.parse(signedJwtPart);

        assertEquals(credentialConfiguration.getVct(), parsed.getJWTClaimsSet().getStringClaim("vct"));
    }
}