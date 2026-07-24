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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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

    private static Stream<JWSSigner> createTestSigner() throws JOSEException {
        return Stream.of(
            new ECDSASigner(
                new ECKeyGenerator(Curve.P_256)
                    .keyID("test-key")
                    .algorithm(JWSAlgorithm.ES256)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate()),
            new Ed25519Signer(
                new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID("test-key")
                    .algorithm(JWSAlgorithm.Ed25519)
                    .keyUse(KeyUse.SIGNATURE)
                    .generate())
            );
    }

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void shouldIssueSingleSdJwtAndStoreVcHash_whenVcHashStorageEnabled(JWSSigner signer) throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);

        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void shouldThrowWhenStatusReferencesIncompatibleWithBatchSize(JWSSigner signer) throws Exception {
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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void shouldNotOverrideProtectedClaimsFromOfferData(JWSSigner signer) throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        when(issuerMetadata.getCredentialConfigurationById(metadataCredentialSupportedId)).thenReturn(credentialConfiguration);

        CredentialOffer offer = createCredentialOffer(Map.of("vct", "malicious", "name", "Alice"));

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void shouldIssueBatchSdJwtAndStoreVcHash_whenMultipleHolderKeys(JWSSigner signer) throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(true);
        mockBatchIssuanceAllowed();
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(metadataCredentialSupportedId, credentialConfiguration));
        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

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
        JWSSigner signer = createTestSigner().findFirst().get();
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        assertEquals(1, credentials.getFirst().split("~").length); // No claim / no disclosure should be added
    }

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void returnedCredentialListIsUnmodifiable(JWSSigner signer) throws Exception {

        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));
        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        List<String> credentials = sdJwtCredential.getCredential(null);

        assertThrows(UnsupportedOperationException.class, () -> credentials.add("another"));
    }

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void whenVcHashStorageDisabled_thenVcHashesNotStored(JWSSigner signer) throws Exception {

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);

        CredentialOffer offer = createCredentialOffer(getSubjectData());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        // vcHashes should not be set when storage disabled
        assertNull(offer.getVcHashes());
    }

    /**
     * Test for when only an array list is included but recursive disclosures are used.
     * This causes the array to be wrapped in a wrapper.
     * The created VC should in decoded form look like
     * {
     * "profile_version": "swiss-profile-vc:1.0.0",
     * "alg": "ES256",
     * "typ": "dc+sd-jwt"
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
    @ParameterizedTest
    @MethodSource("createTestSigner")
    void whenListRecursive(JWSSigner signer) throws Exception {

        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(getOfferDataList());

        CredentialOffer offer = createCredentialOffer(getOfferDataList());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void whenList_withDeeplyNestedObject_thenSuccess(JWSSigner signer) throws Exception {

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
                      "claim": "Nested element",
                      "null_value": null
                    }
                  }
                }
                """;

        var objectMapper = new ObjectMapper();

        Map<String, Object> credentialSubject = objectMapper.readValue(offerDataString, Map.class);

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(credentialSubject);

        CredentialOffer offer = createCredentialOffer(credentialSubject);

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void whenList_withArraysOfArrays_thenSuccess(JWSSigner signer) throws Exception {

        String offerDataString = """
                {
                  "object": {
                    "array_arrays": [
                      1,
                      3.14,
                      "string",
                      [0],
                      [1],
                      [2],
                      {
                        "claim": "Nested element",
                        "other": {
                            "deeply": "nested"
                        }
                      }
                    ]
                  }
                }
                """;

        var objectMapper = new ObjectMapper();

        Map<String, Object> credentialSubject = objectMapper.readValue(offerDataString, Map.class);

        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);
        when(dataIntegrityService.getVerifiedOfferData(any(), any())).thenReturn(credentialSubject);

        CredentialOffer offer = createCredentialOffer(credentialSubject);

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

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
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 3, 0), List.of(0)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 4, 0), List.of(1)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 5, 0), List.of(2)));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 6, "claim"), List.of("Nested element")));
        assertDoesNotThrow(() -> ClaimsPathPointerUtil.validateRequestedClaims(decodedMap, List.of("object", "array_arrays", 6, "other", "deeply"), List.of("nested")));
    }

    private String[] getVcSdJwtParts(String vc) {
        return vc.split("~");
    }

    private Map<String, Object> getSubjectData() {
        return Map.of("foo", "bar");
    }

    private Map<String, Object> getOfferDataList() {
        return Map.of("foo", List.of("bar1", "bar2"));
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

    @ParameterizedTest
    @MethodSource("createTestSigner")
    void shouldAddCredentialMetadataAndNbfExpClaims(JWSSigner signer) throws Exception {
        when(applicationProperties.isEnableVcHashStorage()).thenReturn(false);

        var vctMetadataUri = "https://example/vct.json";
        var vctMetadataUriIntegrity = "vct-uri-int";

        var credentialMetadata = new CredentialOfferMetadata(null, vctMetadataUri, vctMetadataUriIntegrity);

        CredentialOffer offer = createCredentialOffer(getSubjectData());
        offer.setCredentialMetadata(credentialMetadata);

        when(credentialOfferStatusRepository.findByOfferId(offer.getId())).thenReturn(Set.of());

        var sdJwtCredential = spy(new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, jwsSignatureFacade, statusListRepository, credentialOfferStatusRepository));

        doReturn(signer).when(sdJwtCredential).createSigner();
        sdJwtCredential.credentialOffer(offer);
        sdJwtCredential.credentialType(List.of(metadataCredentialSupportedId));

        String sdjwt = sdJwtCredential.getCredential(null).getFirst();
        String signedPart = sdjwt.contains("~") ? sdjwt.split("~")[0] : sdjwt;
        SignedJWT parsed = SignedJWT.parse(signedPart);

        assertEquals(vctMetadataUri, parsed.getJWTClaimsSet().getStringClaim("vct_metadata_uri"));
        assertEquals(vctMetadataUriIntegrity, parsed.getJWTClaimsSet().getStringClaim("vct_metadata_uri#integrity"));

        assertNotNull(parsed.getJWTClaimsSet().getClaim("iat"));
    }
}