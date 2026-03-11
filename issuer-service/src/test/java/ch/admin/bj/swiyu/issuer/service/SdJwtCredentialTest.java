package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.BatchCredentialIssuance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.authlete.sd.Disclosure;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.stream.Stream;

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
        DidJwk didJwk1 = DidJwk.createFromJsonString(ecJWK.toPublicJWK().toJSONString());
        ECKey ecJWK2 = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        DidJwk didJwk2 = DidJwk.createFromJsonString(ecJWK2.toPublicJWK().toJSONString());

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> subject.getCredential(List.of(didJwk1, didJwk2)));
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

    @Test
    void shouldIssueBatchSdJwtAndStoreVcHash_whenMultipleHolderKeys() throws Exception {
        var configurationId = "metadata-supported";
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, config));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(config);
        when(issuerMetadata.isBatchIssuanceAllowed()).thenReturn(true);
        doReturn(new BatchCredentialIssuance(10)).when(issuerMetadata).getBatchCredentialIssuance();

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

        // create two holder public keys
        ECKey ecJWK1 = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        ECKey ecJWK2 = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        DidJwk didJwk1 = DidJwk.createFromJsonString(ecJWK1.toPublicJWK().toJSONString());
        DidJwk didJwk2 = DidJwk.createFromJsonString(ecJWK2.toPublicJWK().toJSONString());

        List<String> credentials = sdJwtCredential.getCredential(List.of(didJwk1, didJwk2));

        assertNotNull(credentials);
        assertEquals(2, credentials.size());

        // ensure vc hashes were collected for both credentials
        assertNotNull(offer.getVcHashes());
        assertEquals(2, offer.getVcHashes().size());
    }

    @Test
    void returnedCredentialListIsUnmodifiable() throws Exception {
        var configurationId = "metadata-supported";
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(credentialConfiguration);

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

        assertThrows(UnsupportedOperationException.class, () -> credentials.add("another"));
    }

    @Test
    void whenVcHashStorageDisabled_thenVcHashesNotStored() throws Exception {
        var configurationId = "metadata-supported";
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
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

        // vcHashes should not be set when storage disabled
        assertNull(offer.getVcHashes());
    }

    @Test
    void whenList() throws Exception {
        var configurationId = "metadata-supported";
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, config));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(config);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(Map.of("foo", List.of("bar1", "bar2")));

        CredentialOffer offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(configurationId))
                .offerData(Map.of("foo", List.of("bar1", "bar2")))
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(configurationId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = credentials.getFirst().split("~");
        assertEquals(3, sdJwtComponents.length);

        // check if disclosures contain the list values
        var disclosures = Stream.of(sdJwtComponents[1], sdJwtComponents[2]).map(Disclosure::new).toList();

        // claim name should not be set in here
        disclosures.forEach(d -> assertNull(d.getClaimName()));

        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtComponents[0]);
        assertEquals(2, ((List<Map<String, String>>) signedJWT.getJWTClaimsSet().getClaim("foo")).size());
        assertTrue(((List<Map<String, String>>) signedJWT.getJWTClaimsSet().getClaim("foo")).stream().allMatch(entry -> entry.containsKey("...")));
    }

    @Test
    void whenListRecursive() throws Exception {
        var configurationId = "metadata-supported";
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, config));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(config);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(Map.of("foo", List.of("bar1", "bar2")));

        CredentialOffer offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(configurationId))
                .offerData(Map.of("foo", List.of("bar1", "bar2")))
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(configurationId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = credentials.getFirst().split("~");
        assertEquals(4, sdJwtComponents.length);

        // check if disclosures contain the list values
        var disclosures = Stream.of(sdJwtComponents[1], sdJwtComponents[2]).map(Disclosure::new).toList();

        // claim name should not be set in here
        disclosures.forEach(d -> assertNull(d.getClaimName()));

        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtComponents[0]);

        // check that only 1 sd claim is set
        assertEquals(1, ((List<String>) signedJWT.getJWTClaimsSet().getClaims().get("_sd")).size());
    }
}