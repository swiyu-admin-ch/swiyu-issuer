package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CredentialEndpointResponseDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CredentialObjectDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CredentialBuilderTest {

    private static final String CREDENTIAL_SUPPORTED_ID = "credential-supported-id";
    private ApplicationProperties applicationProperties;
    private IssuerMetadata issuerMetadata;
    private CredentialBuilder builder;
    private ObjectMapper objectMapper;
    private StatusListRepository statusListRepository;
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        issuerMetadata = mock(IssuerMetadata.class);
        DataIntegrityService dataIntegrityService = mock(DataIntegrityService.class);
        JwsSignatureFacade jwsSignatureFacade = mock(JwsSignatureFacade.class);
        statusListRepository = mock(StatusListRepository.class);
        credentialOfferStatusRepository = mock(CredentialOfferStatusRepository.class);
        objectMapper = new ObjectMapper();

        builder = spy(new TestCredentialBuilder(applicationProperties, issuerMetadata, dataIntegrityService, jwsSignatureFacade,
                statusListRepository, credentialOfferStatusRepository));
    }

    @Test
    void credentialOffer_credentialOffer_thenSuccess() {
        CredentialOffer offer = mock(CredentialOffer.class);
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("id"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of("id", config));

        CredentialBuilder result = builder.credentialOffer(offer);

        assertSame(builder, result);
        assertSame(offer, builder.getCredentialOffer());
        assertSame(config, builder.getCredentialConfiguration());
    }

    @Test
    void credentialOffer_missingConfig_throwsOID4VCIException() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("missing-supported-id"));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of());

        assertThrows(Oid4vcException.class, () -> builder.credentialOffer(offer));
    }

    @Test
    void credentialOffer_credentialResponseEncryption_thenSuccess() {
        CredentialResponseEncryptionClass credentialResponseEncryption = mock(CredentialResponseEncryptionClass.class);
        IssuerCredentialResponseEncryption issuerCredentialResponseEncryption = mock(IssuerCredentialResponseEncryption.class);

        when(issuerMetadata.getResponseEncryption()).thenReturn(issuerCredentialResponseEncryption);

        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), credentialResponseEncryption);

        assertNotNull(builder.getCredentialResponseEncryptor());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"credential"})
    void credentialOffer_buildCredentialEnvelope_thenSuccess(String input) throws IOException {

        List<CredentialObjectDto> credentialObjectDto = List.of(new CredentialObjectDto(input));
        CredentialEndpointResponseDto credentialResponseDtoV2 = new CredentialEndpointResponseDto(credentialObjectDto, null, null);
        var expectedCredentialWrapper = objectMapper.writeValueAsString(credentialResponseDtoV2);

        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);
        builder.holderBindings(List.of());
        var inputList = new LinkedList<String>();
        inputList.add(input);
        doReturn(inputList).when(builder).getCredential(Mockito.anyList());

        var result = builder.buildCredentialEnvelope();

        // check if getCredential has been called without a param
        verify(builder).getCredential(Mockito.anyList());

        assertEquals("application/json", result.getContentType());

        // can only contain 1 credential
        assertEquals(1, objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDto.class).credentials().size());
        assertEquals(expectedCredentialWrapper, result.getOid4vciCredentialJson());
    }

    @Test
    void credentialOffer_multipleProofs_thenSuccess() throws JOSEException, IOException {
        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);

        doReturn(List.of("credential")).when(builder).getCredential(null);

        var privateKeys = List.of(createPrivateKey(), createPrivateKey());

        var list = privateKeys.stream().map(jwk -> {
            try {
                return TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), "c_nonce", ProofType.JWT.getClaimTyp(), true);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
        }).toList();

        builder.holderBindings(list);
        List<DidJwk> didJwks = list.stream()
                .map(DidJwk::createFromJsonString)
                .toList();

        doReturn(List.of("credential1")).when(builder).getCredential(List.of(didJwks.getFirst()));
        doReturn(List.of("credential2")).when(builder).getCredential(List.of(didJwks.get(1)));

        var result = builder.buildCredentialEnvelope();

        verify(builder, Mockito.times(1)).getCredential(any());

        assertEquals("application/json", result.getContentType());
        assertEquals(HttpStatus.OK, result.getHttpStatus());

        // can only contain 1 credential
        assertEquals(2, objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDto.class).credentials().size());
    }

    @Test
    void buildDeferredCredential_thenSuccess() throws IOException {
        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);

        var expectedInterval = 10L;
        when(applicationProperties.getMinDeferredOfferIntervalSeconds()).thenReturn(expectedInterval);

        var transactionId = UUID.randomUUID();
        var result = builder.buildDeferredCredential(transactionId);

        // status must be accepted
        assertEquals(HttpStatus.ACCEPTED, result.getHttpStatus());
        assertEquals("application/json", result.getContentType());
        var payload = objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDto.class);
        // transaction id and interval must be set
        assertEquals(transactionId.toString(), payload.transactionId());
        assertEquals(expectedInterval, payload.interval());
    }

    @Test
    void buildEnvelopeDto_thenSuccess() {
        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);
        List<CredentialObjectDto> credentialObjectDto = List.of(new CredentialObjectDto("credential"));
        CredentialEndpointResponseDto credentialResponseDtoV2 = new CredentialEndpointResponseDto(credentialObjectDto, null, null);
        var response = builder.buildEnvelopeDto(credentialResponseDtoV2);

        assertEquals("application/json", response.getContentType());
        assertEquals(HttpStatus.OK, response.getHttpStatus());

        verify(builder).buildEnvelopeDto(credentialResponseDtoV2, HttpStatus.OK);
    }

    @Test
    void buildEnvelopeDto_withEncryption_thenSuccess() throws JOSEException {

        var issuerCredentialResponseEncryption = new IssuerCredentialResponseEncryption();
        issuerCredentialResponseEncryption.setAlgValuesSupported(List.of("ECDH-ES"));
        issuerCredentialResponseEncryption.setEncValuesSupported(List.of("A128GCM"));

        when(issuerMetadata.getResponseEncryption()).thenReturn(issuerCredentialResponseEncryption);
        var jwk = createPrivateKey().toPublicJWK().toJSONObject();
        CredentialResponseEncryptionClass encryptor = new CredentialResponseEncryptionClass(jwk, "ECDH-ES", "A128GCM");

        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), encryptor);

        when(issuerMetadata.getResponseEncryption()).thenReturn(issuerCredentialResponseEncryption);

        List<CredentialObjectDto> credentialObjectDto = List.of(new CredentialObjectDto("credential"));
        CredentialEndpointResponseDto credentialResponseDtoV2 = new CredentialEndpointResponseDto(credentialObjectDto, null, null);
        var response = builder.buildEnvelopeDto(credentialResponseDtoV2);

        assertEquals("application/jwt", response.getContentType());
    }

    @Test
    void getStatusReferences_thenReturnsAggregatedReferences() {

        UUID offerId = UUID.randomUUID();
        UUID statusListId1 = UUID.randomUUID();
        UUID statusListId2 = UUID.randomUUID();

        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getId()).thenReturn(offerId);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(CREDENTIAL_SUPPORTED_ID));

        var test = mock(CredentialConfiguration.class);
        when(test.getVctMetadataUri()).thenReturn("https://example.com/vct-metadata");

        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(CREDENTIAL_SUPPORTED_ID, mock(CredentialConfiguration.class)));

        // two status entries pointing to two different status lists
        CredentialOfferStatusKey key1 = new CredentialOfferStatusKey(offerId, statusListId1, 5);
        CredentialOfferStatusKey key2 = new CredentialOfferStatusKey(offerId, statusListId2, 7);

        CredentialOfferStatus status1 = CredentialOfferStatus.builder().id(key1).build();
        CredentialOfferStatus status2 = CredentialOfferStatus.builder().id(key2).build();

        when(credentialOfferStatusRepository.findByOfferId(offerId)).thenReturn(Set.of(status1, status2));

        StatusList sl1 = StatusList.builder().id(statusListId1).uri("https://example.com/status/1").build();
        StatusList sl2 = StatusList.builder().id(statusListId2).uri("https://example.com/status/2").build();

        when(statusListRepository.findById(statusListId1)).thenReturn(Optional.of(sl1));
        when(statusListRepository.findById(statusListId2)).thenReturn(Optional.of(sl2));

        builder.credentialOffer(offer);

        Map<String, List<ch.admin.bj.swiyu.issuer.domain.credentialoffer.VerifiableCredentialStatusReference>> refs = builder.getStatusReferences();

        assertEquals(2, refs.size());
        assertTrue(refs.containsKey(sl1.getUri()));
        assertTrue(refs.containsKey(sl2.getUri()));
        assertEquals(1, refs.get(sl1.getUri()).size());
        assertEquals(1, refs.get(sl2.getUri()).size());

        var ref = refs.get(sl1.getUri()).getFirst();
        assertEquals(sl1.getUri(), ref.getIdentifier());
        // TokenStatusListReference exposes idx as first param; ensure the index is correct
        assertEquals(5, ((ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListReference) ref).idx());
    }

    @Test
    void freeUnusedStatusReferences_deletesSuperfluousStatuses() {
        UUID offerId = UUID.randomUUID();
        UUID statusListId1 = UUID.randomUUID();
        UUID statusListId2 = UUID.randomUUID();

        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getId()).thenReturn(offerId);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(CREDENTIAL_SUPPORTED_ID));
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(Map.of(CREDENTIAL_SUPPORTED_ID, mock(CredentialConfiguration.class)));

        CredentialOfferStatusKey key1 = new CredentialOfferStatusKey(offerId, statusListId1, 3);
        CredentialOfferStatusKey key2 = new CredentialOfferStatusKey(offerId, statusListId2, 9);

        CredentialOfferStatus status1 = CredentialOfferStatus.builder().id(key1).build();
        CredentialOfferStatus status2 = CredentialOfferStatus.builder().id(key2).build();

        when(credentialOfferStatusRepository.findByOfferId(offerId)).thenReturn(Set.of(status1, status2));

        StatusList sl1 = StatusList.builder().id(statusListId1).uri("https://example.com/status/1").build();
        StatusList sl2 = StatusList.builder().id(statusListId2).uri("https://example.com/status/2").build();

        when(statusListRepository.findById(statusListId1)).thenReturn(Optional.of(sl1));
        when(statusListRepository.findById(statusListId2)).thenReturn(Optional.of(sl2));

        builder.credentialOffer(offer);

        // mark only the first status as used
        var usedRef = new ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListReference(3, sl1.getUri());

        builder.freeUnusedStatusReferences(List.of(usedRef));

        ArgumentCaptor<Collection<CredentialOfferStatus>> captor = ArgumentCaptor.forClass(Collection.class);
        verify(credentialOfferStatusRepository, times(1)).deleteAll(captor.capture());

        Collection<CredentialOfferStatus> deleted = captor.getValue();
        assertEquals(1, deleted.size());
        assertTrue(deleted.contains(status2));
    }

    private ECKey createPrivateKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    // subclass for testing
    static class TestCredentialBuilder extends CredentialBuilder {
        TestCredentialBuilder(ApplicationProperties applicationProperties, IssuerMetadata issuerMetadata, DataIntegrityService dataIntegrityService, JwsSignatureFacade jwsSignatureFacade,
                              StatusListRepository statusListRepository, CredentialOfferStatusRepository credentialOfferStatusRepository) {
            super(applicationProperties, issuerMetadata, dataIntegrityService, statusListRepository, jwsSignatureFacade, credentialOfferStatusRepository);
        }

        @Override
        public List<String> getCredential(List<DidJwk> didJwk) {
            if (didJwk == null) {
                return List.of(getCredentialSingle(null));
            }
            return didJwk.stream().map(this::getCredentialSingle).toList();
        }

        @Override
        JWSSigner createSigner() {
            return null;
        }

        protected String getCredentialSingle(DidJwk didJwk) {
            return didJwk == null ? "credential" : "credential-" + didJwk.getDidJwk();
        }
    }
}