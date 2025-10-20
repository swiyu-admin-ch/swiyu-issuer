package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointResponseDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialObjectDtoV2;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
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
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CredentialBuilderTest {

    private ApplicationProperties applicationProperties;
    private IssuerMetadata issuerMetadata;

    private CredentialBuilder builder;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        issuerMetadata = mock(IssuerMetadata.class);
        DataIntegrityService dataIntegrityService = mock(DataIntegrityService.class);
        JWSSigner signer = mock(JWSSigner.class);
        SignatureService signatureService = mock(SignatureService.class);
        StatusListRepository statusListRepository = mock(StatusListRepository.class);
        CredentialOfferStatusRepository credentialOfferStatusRepository = mock(CredentialOfferStatusRepository.class);
        objectMapper = new ObjectMapper();

        builder = spy(new TestCredentialBuilder(applicationProperties, issuerMetadata, dataIntegrityService, signatureService,
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
    void credentialOffer_buildCredentialEnvelopeV2_thenSuccess(String input) throws IOException {

        List<CredentialObjectDtoV2> credentialObjectDtoV2 = List.of(new CredentialObjectDtoV2(input));
        CredentialEndpointResponseDtoV2 credentialResponseDtoV2 = new CredentialEndpointResponseDtoV2(credentialObjectDtoV2, null, null);
        var expectedCredentialWrapper = objectMapper.writeValueAsString(credentialResponseDtoV2);

        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);
        builder.holderBindings(List.of());
        var inputList = new LinkedList<String>();
        inputList.add(input);
        doReturn(inputList).when(builder).getCredential(Mockito.anyList());

        var result = builder.buildCredentialEnvelopeV2();

        // check if getCredential has been called without a param
        verify(builder).getCredential(Mockito.anyList());

        assertEquals("application/json", result.getContentType());

        // can only contain 1 credential
        assertEquals(1, objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDtoV2.class).credentials().size());
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

        var result = builder.buildCredentialEnvelopeV2();

        verify(builder, Mockito.times(1)).getCredential(any());

        assertEquals("application/json", result.getContentType());
        assertEquals(HttpStatus.OK, result.getHttpStatus());

        // can only contain 1 credential
        assertEquals(2, objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDtoV2.class).credentials().size());
    }

    @Test
    void buildDeferredCredentialV2_thenSuccess() throws IOException {
        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);

        var expectedInterval = 10L;
        when(applicationProperties.getMinDeferredOfferIntervalSeconds()).thenReturn(expectedInterval);

        var transactionId = UUID.randomUUID();
        var result = builder.buildDeferredCredentialV2(transactionId);

        // status must be accepted
        assertEquals(HttpStatus.ACCEPTED, result.getHttpStatus());
        assertEquals("application/json", result.getContentType());
        var payload = objectMapper.readValue(result.getOid4vciCredentialJson(), CredentialEndpointResponseDtoV2.class);
        // transaction id and interval must be set
        assertEquals(transactionId.toString(), payload.transactionId());
        assertEquals(expectedInterval, payload.interval());
    }

    @Test
    void buildEnvelopeDto_thenSuccess() {
        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), null);
        List<CredentialObjectDtoV2> credentialObjectDtoV2 = List.of(new CredentialObjectDtoV2("credential"));
        CredentialEndpointResponseDtoV2 credentialResponseDtoV2 = new CredentialEndpointResponseDtoV2(credentialObjectDtoV2, null, null);
        var response = builder.buildEnvelopeDto(credentialResponseDtoV2);

        assertEquals("application/json", response.getContentType());
        assertEquals(HttpStatus.OK, response.getHttpStatus());

        verify(builder).buildEnvelopeDto(credentialResponseDtoV2, HttpStatus.OK);
    }

    @Test
    void buildEnvelopeDto_withEncryption_thenSuccess() throws JOSEException {

        var issuerCredentialResponseEncryption = new IssuerCredentialResponseEncryption();
        issuerCredentialResponseEncryption.setAlgValuesSupported(List.of("ECDH-ES+A128KW"));
        issuerCredentialResponseEncryption.setEncValuesSupported(List.of("A128CBC-HS256"));

        when(issuerMetadata.getResponseEncryption()).thenReturn(issuerCredentialResponseEncryption);
        var jwk = createPrivateKey().toPublicJWK().toJSONObject();
        CredentialResponseEncryptionClass encryptor = new CredentialResponseEncryptionClass(jwk, "ECDH-ES+A128KW", "A128CBC-HS256");

        builder.credentialResponseEncryption(issuerMetadata.getResponseEncryption(), encryptor);

        when(issuerMetadata.getResponseEncryption()).thenReturn(issuerCredentialResponseEncryption);

        List<CredentialObjectDtoV2> credentialObjectDtoV2 = List.of(new CredentialObjectDtoV2("credential"));
        CredentialEndpointResponseDtoV2 credentialResponseDtoV2 = new CredentialEndpointResponseDtoV2(credentialObjectDtoV2, null, null);
        var response = builder.buildEnvelopeDto(credentialResponseDtoV2);

        assertEquals("application/jwt", response.getContentType());
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
        TestCredentialBuilder(ApplicationProperties applicationProperties, IssuerMetadata issuerMetadata, DataIntegrityService dataIntegrityService, SignatureService signatureService,
                              StatusListRepository statusListRepository, CredentialOfferStatusRepository credentialOfferStatusRepository) {
            super(applicationProperties, issuerMetadata, dataIntegrityService, statusListRepository, signatureService, credentialOfferStatusRepository);
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