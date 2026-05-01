package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.HolderKeyBinding;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.offer.ClaimsPathPointerUtil;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectDecoder;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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

        CredentialOffer offer = createCredentialOffer(getSubjectData());

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

        CredentialOffer offer = createCredentialOffer(Map.of());

        // prepare 1 status references
        var statusListId = UUID.randomUUID();
        var key = new CredentialOfferStatusKey(offer.getId(), statusListId, 1);
        var status = CredentialOfferStatus.builder().id(key).build();
        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of(status));

        // status list referenced
        StatusList sl = StatusList.builder().id(statusListId).uri("https://example.com/status/1").build();
        when(statusListRepository.findById(statusListId)).thenReturn(Optional.of(sl));

        // issuer metadata allows batch issuance
        mockBatchIssuanceAllowed();

        var subject = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        JWSSigner signer = createTestSigner();
        doReturn(signer).when(subject).createSigner();

        subject.credentialOffer(offer);

        // provide two holder keys so batch size becomes 2
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        HolderKeyBinding holderKeyBinding1 = new HolderKeyBinding(ecJWK.toPublicJWK().toJSONString());
        ECKey ecJWK2 = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        HolderKeyBinding holderKeyBinding2 = new HolderKeyBinding(ecJWK2.toPublicJWK().toJSONString());

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> subject.getCredential(List.of(holderKeyBinding1, holderKeyBinding2)));
    }

    @Test
    void shouldNotOverrideProtectedClaimsFromOfferData() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(metadataCredentialSupportedId)).thenReturn(credentialConfiguration);

        CredentialOffer offer = createCredentialOffer(Map.of("vct", "malicious", "name", "Alice"));

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
        mockBatchIssuanceAllowed();
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        // create two holder public keys
        // provide two holder keys so batch size becomes 2
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        HolderKeyBinding holderKeyBinding1 = new HolderKeyBinding(ecJWK.toPublicJWK().toJSONString());
        ECKey ecJWK2 = new ECKeyGenerator(Curve.P_256).keyID("k2").generate();
        HolderKeyBinding holderKeyBinding2 = new HolderKeyBinding(ecJWK2.toPublicJWK().toJSONString());

        List<String> credentials = sdJwtCredential.getCredential(List.of(holderKeyBinding1, holderKeyBinding2));

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

        CredentialOffer offer = createCredentialOffer(Map.of(value, "bar"));

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

        CredentialOffer offer = createCredentialOffer(getSubjectData());

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

        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        // vcHashes should not be set when storage disabled
        assertNull(offer.getVcHashes());
    }

    /**
     * Test for a VC with array disclosures which should looks in decoded form similar to
     * {
     * "profile_version": "swiss-profile-vc:1.0.0",
     * "alg": "ES256",
     * "typ": "vc+sd-jwt"
     * }.{
     * "iss": "did:example:issuer",
     * "iat": 1774310400,
     * "vct": "urn:vct:test:1",
     * "_sd_alg": "sha-256",
     * "foo": [
     * {
     * "...": "qlO5w7znGvkU7DWheg0s5fLvNuIB5Pw_oD9OxpenmVY"
     * },
     * {
     * "...": "RtdAx5HYC6cNAQDJFsKbiRlBYQRFG8f0uvuju9BYNyY"
     * }
     * ]
     * }~["PVAEARUcGDMYACiLwsA1DQ","bar1"]~["SjXMEuJeI0dHQmbW4gZ_Zg","bar2"]~
     */
    @Test
    void whenArrayDisclosure_withRecursionDisabled_thenSuccess() throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(getOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtParts(credentials.getFirst());
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

    /**
     * Test for when only an array list is included but recursive disclosures are used.
     * This causes the array to be wrapped in a wrapper.
     * The created VC should in decoded form look like
     * {
     * "profile_version": "swiss-profile-vc:1.0.0",
     * "alg": "ES256",
     * "typ": "vc+sd-jwt"
     * }.{
     * "iss": "did:example:issuer",
     * "_sd": [
     * "j-HmgNvc54JKVVReI0Eclng-QiFJj8M3Vv_yktd0uv4"
     * ],
     * "iat": 1774310400,
     * "vct": "urn:vct:test:1",
     * "_sd_alg": "sha-256"
     * }~["IXJ7Np8MwLB5do1Yxsil-Q","bar1"]~["Y4tA7pvDr8mNnd1I0doxLw","bar2"]
     * ~["Nxjorg9T_qEP28rC-xJ5qA","foo",[{"...":"AAL7lEZtrahouJboEpiHOz72MYY7IX9olGcjzUWkKDw"},{"...":"DlrJJveRk3V_lO5-4Zgx1_l_nR6XAYp0b96LW9Co08g"}]]
     */
    @Test
    void whenListRecursive() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(getOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtParts(credentials.getFirst());
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
    void whenListRecursive_withObject_shouldBeFlattened_thenSuccess() throws Exception {

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getNestedOfferDataList());

        CredentialOffer offer = createCredentialOffer(getNestedOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtParts(credentials.getFirst());
        // todo check
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
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getNestedOfferDataList());

        CredentialOffer offer = createCredentialOffer(getNestedOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtComponents = getVcSdJwtParts(credentials.getFirst());
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

    @Test
    void whenList_withDeeplyNestedObject_thenSuccess() throws Exception {

        String offerDataString = """
                {
                  "object": {
                    "claim": "Claim level 1",
                    "array_integers": [
                      1,
                      2,
                      3
                    ],
                    "array_arrays": [
                      [0],
                      [1],
                      [2],
                      {
                        "claim": "Nested element"
                      }
                    ],
                    "array_objects": [
                      {
                        "claim": "Nested object element 1"
                      },
                      {
                        "claim": "Nested object element 2"
                      }
                    ],
                    "object": {
                      "claim": "Nested element"
                    }
                  }
                }
                """;

        var objectMapper = new ObjectMapper();

        Map<String, Object> credentialSubject = objectMapper.readValue(offerDataString, Map.class);

        when(applicationProperties.isRecursiveDisclosureEnabled()).thenReturn(true);
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(credentialSubject);

        CredentialOffer offer = createCredentialOffer(credentialSubject);

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        JWSSigner signer = createTestSigner();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        // should contain 2 disclosures (for every list element) + jwt (no binding)
        var sdJwtDisclosures = getVcSdJwtParts(credentials.getFirst());

        // check if disclosures contain the list values
        var disclosuresString = List.of(sdJwtDisclosures).subList(1, sdJwtDisclosures.length);
        var disclosures = disclosuresString.stream().map(Disclosure::parse).toList();
        
        // should contain a foo claim with the list values in the disclosures
        SignedJWT signedJWT = SignedJWT.parse(sdJwtDisclosures[0]);

        SDObjectDecoder decoder = new SDObjectDecoder();

        Map<String, Object> decodedMap = decoder.decode(signedJWT.getJWTClaimsSet().toJSONObject(), disclosures);
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "claim"), List.of("Claim level 1")));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_integers", 0), List.of(1)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_integers", 1), List.of(2)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_integers", 2), List.of(3)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_objects", 0, "claim"), List.of("Nested object element 1")));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_objects", 1, "claim"), List.of("Nested object element 2")));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "object", "claim"), List.of("Nested element")));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 0, 0), List.of(0)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 1, 0), List.of(1)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 2, 0), List.of(2)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 3, "claim"), List.of("Nested element")));
    }

    private String[] getVcSdJwtParts(String vc) {
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

    private CredentialOffer createCredentialOffer(Map<String, Object> offerData) {
        var offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(null)
                .metadataCredentialSupportedId(List.of("metadata-supported"))
                .offerData(offerData)
                .credentialRequest(new CredentialRequestClass("vc+sd-jwt", null, null))
                .build();

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        return offer;
    }

    private void mockBatchIssuanceAllowed() {
        when(issuerMetadata.isBatchIssuanceAllowed()).thenReturn(true);
        when(issuerMetadata.getIssuanceBatchSize()).thenReturn(10);
    }

    @Test
    void shouldAddCredentialMetadataAndNbfExpClaims() throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);

        var vctIntegrity = "vct-int";
        var vctMetadataUri = "https://example/vct.json";
        var vctMetadataUriIntegrity = "vct-uri-int";

        var credentialMetadata = new CredentialOfferMetadata(null, vctIntegrity, vctMetadataUri, vctMetadataUriIntegrity);

        CredentialOffer offer = createCredentialOffer(getSubjectData());
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