package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(metadataCredentialSupportedId)).thenReturn(credentialConfiguration);
    }

    private JWSSigner createTestSigner() throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("test-key")
                .generate();
        return new ECDSASigner(ecJWK);
    }

    @Test
    void shouldIssueSingleSdJwtAndStoreVcHash_whenVcHashStorageEnabled() throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

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

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, Map.of());

        // prepare 1 status references
        var statusListId = UUID.randomUUID();
        var key = new CredentialOfferStatusKey(offer.getId(), statusListId, 1);
        var status = CredentialOfferStatus.builder().id(key).build();
        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of(status));

        // status list referenced
        StatusList sl = StatusList.builder().id(statusListId).uri("https://example.com/status/1").build();
        when(statusListRepository.findById(statusListId)).thenReturn(Optional.of(sl));

        // issuer metadata allows batch issuance
        mockBatchIssuanceAllowed(10);

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
        var holderKeys = List.of(didJwk1, didJwk2);
        assertThrows(IllegalStateException.class, () -> subject.getCredential(holderKeys));
    }

    @Test
    void shouldNotOverrideProtectedClaimsFromOfferData() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(metadataCredentialSupportedId)).thenReturn(credentialConfiguration);

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, Map.of("vct", "malicious", "name", "Alice"));

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

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);
        mockBatchIssuanceAllowed(10);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

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

    @ParameterizedTest
    @ValueSource(strings = {"iss",
            "nbf",
            "exp",
            "iat",
            "cnf",
            "vct",
            "status",
            "_sd",
            "_sd_alg",
            "sd_hash",
            "..."})
    void whenGetCredential_withReservedKey_doesNotAddValue_thenSuccess(String value) throws Exception {

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, Map.of(value, "bar"));

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(Map.of(value, "bar"));
        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        assertEquals(1, credentials.getFirst().split("~").length); // No claim / no disclosure should be added
    }

    @Test
    void returnedCredentialListIsUnmodifiable() throws Exception {

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        assertThrows(UnsupportedOperationException.class, () -> credentials.add("another"));
    }

    @Test
    void whenVcHashStorageDisabled_thenVcHashesNotStored() throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        // vcHashes should not be set when storage disabled
        assertNull(offer.getVcHashes());
    }

    @Test
    void whenArrayDisclosure_withRecursionDisabled_thenSuccess() throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtPars(credentials.getFirst());
        assertEquals(3, sdJwtComponents.length);

        // check if disclosures contain the list values
        var disclosures = Stream.of(sdJwtComponents[1], sdJwtComponents[2]).map(Disclosure::new).toList();

        // claim name should not be set in here
        disclosures.forEach(d -> assertNull(d.getClaimName()));

        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtComponents[0]);
        List<Map<String, String>> fooClaim = (List<Map<String, String>>) signedJWT.getJWTClaimsSet().getClaim("foo");
        assertEquals(2, fooClaim.size());
        assertTrue(fooClaim.stream().allMatch(entry -> entry.containsKey("...")));
    }

    @Test
    void whenListRecursive() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtPars(credentials.getFirst());
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

    @Test
    void whenObjectRecursive() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getNestedSubjectData());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getNestedSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        SDObjectBuilder sdJwtBuilder = new SDObjectBuilder();
        List<Disclosure> disclosures = new ArrayList<>();
        List<Disclosure> embeddedElements = new ArrayList<>();
        List<Disclosure> discs = sdJwtCredential.handleClaimsRecursive(sdJwtBuilder, disclosures, getNestedSubjectData(), embeddedElements);

        // test + address claim should be present
        assertEquals(2, discs.size());

        // test + address + all address claims should be present in the disclosures = 6 disclosures in total
        assertEquals(6, disclosures.size());
    }

    @Test
    void whenGetCredential_withRecursivelyNested_thenSuccess() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getNestedSubjectData());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getNestedSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        var sdJwtComponents = getVcSdJwtPars(sdJwtCredential.getCredential(null).getFirst());

        // should contain 1 jwt + 5 address-disclosures + other disclosure (no key binding) for the test claim = 7 disclosures in total
        assertEquals(7, sdJwtComponents.length);

        // check if disclosures contain the list values
        var disclosures = Stream.of(sdJwtComponents[1], sdJwtComponents[2]).map(Disclosure::new).toList();

        // claim name should not be set in here
        disclosures.forEach(d -> assertNull(d.getClaimName()));

        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtComponents[0]);

        // should contain 2 _sd elements (address and test claim)
        assertEquals(2, ((List<String>) signedJWT.getJWTClaimsSet().getClaims().get("_sd")).size());
    }

    @Test
    void whenListRecursive_withObject_shouldBeFlattened_thenSuccess() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getNestedOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtPars(credentials.getFirst());
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

    @Test
    void whenList_withObject_shouldBeFlattened_thenSuccess() throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getNestedOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtPars(credentials.getFirst());
        assertEquals(3, sdJwtComponents.length);

        // check if disclosures contain the list values
        var disclosures = Stream.of(sdJwtComponents[1], sdJwtComponents[2]).map(Disclosure::new).toList();

        // claim name should not be set in here -> as it is an array element, the claim name is not set in the disclosure but only the path with "..."
        disclosures.forEach(d -> assertNull(d.getClaimName()));

        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtComponents[0]);

        var fooClaim = (List<Map<String, String>>) signedJWT.getJWTClaimsSet().getClaim("foo");
        assertEquals(2, fooClaim.size());
        assertTrue(fooClaim.stream().allMatch(entry -> entry.containsKey("...")));
    }

    private String[] getVcSdJwtPars(String vc) {
        return vc.split("~");
    }

    private Map<String, Object> getSubjectData() {
        return Map.of("foo", "bar");
    }

    private Map<String, Object> getNestedSubjectData() {
        var offerAddressData = Map.of("street_address", "123 Main St", "locality", "Anytown", "region", "Anystate", "country", "US");
        return Map.of("test", "test", "address", offerAddressData);
    }

    private Map<String, Object> getOfferDataList() {
        return Map.of("foo", List.of("bar1", "bar2"));
    }

    private Map<String, Object> getNestedOfferDataList() {
        Map<String, Object> nestedObject1 = Map.of("nestedKey1", "nestedValue1");
        Map<String, Object> nestedObject2 = Map.of("nestedKey2", "nestedValue2");

        return Map.of("foo", List.of(nestedObject1, nestedObject2));
    }

    private CredentialOffer createCredentialOffer(String configurationId, Map<String, Object> offerData) {
        var offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of(configurationId))
                .offerData(offerData)
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        return offer;
    }

    private CredentialConfiguration mockCredentialConfiguration(String configurationId) {
        CredentialConfiguration config = CredentialConfiguration.builder()
                .format(SdJwtCredential.SD_JWT_FORMAT)
                .vct("urn:vct:test:1")
                .build();

        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(configurationId, config));
        when(issuerMetadata.getCredentialConfigurationById(configurationId)).thenReturn(config);

        return config;
    }

    private void mockBatchIssuanceAllowed(int batchSize) {
        when(issuerMetadata.isBatchIssuanceAllowed()).thenReturn(true);
        when(issuerMetadata.getIssuanceBatchSize()).thenReturn(batchSize);
    }

    @Test
    void shouldAddCredentialMetadataAndNbfExpClaims() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);

        var vctIntegrity = "vct-int";
        var vctMetadataUri = "https://example/vct.json";
        var vctMetadataUriIntegrity = "vct-uri-int";

        var credentialMetadata = new CredentialOfferMetadata(null, vctIntegrity, vctMetadataUri, vctMetadataUriIntegrity);

        CredentialOffer offer = createCredentialOffer(metadataCredentialSupportedId, getSubjectData());
        offer.setCredentialMetadata(credentialMetadata);

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        String sdjwt = sdJwtCredential.getCredential(null).getFirst();
        String signedPart = sdjwt.contains("~") ? sdjwt.split("~")[0] : sdjwt;
        SignedJWT parsed = SignedJWT.parse(signedPart);

        assertEquals(vctIntegrity, parsed.getJWTClaimsSet().getStringClaim("vct#integrity"));
        assertEquals(vctMetadataUri, parsed.getJWTClaimsSet().getStringClaim("vct_metadata_uri"));
        assertEquals(vctMetadataUriIntegrity, parsed.getJWTClaimsSet().getStringClaim("vct_metadata_uri#integrity"));

        assertNotNull(parsed.getJWTClaimsSet().getClaim("iat"));
    }
}