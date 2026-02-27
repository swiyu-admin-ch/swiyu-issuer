package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.BatchCredentialIssuance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HolderBindingServiceTest {

    private final String supportedCredentialId = "this-is-a-supported-credential-id";
    private IssuerMetadata issuerMetadata;
    private NonceService nonceService;
    private HolderBindingService holderBindingService;
    private List<ECKey> holderKeys;
    private CredentialOffer offer;
    private CredentialConfiguration config;
    private CredentialManagement management;

    @BeforeEach
    void setUp() {
        issuerMetadata = mock(IssuerMetadata.class);
        when(issuerMetadata.getCredentialIssuer()).thenReturn("did:example:issuer");
        OpenIdIssuerConfiguration openIdIssuerConfiguration = mock(OpenIdIssuerConfiguration.class);
        when(openIdIssuerConfiguration.getIssuerMetadata()).thenReturn(issuerMetadata);
        nonceService = mock(NonceService.class);
        KeyAttestationService keyAttestationService = mock(KeyAttestationService.class);
        ApplicationProperties applicationProperties = mock(ApplicationProperties.class);
        var metadataService = mock(MetadataService.class);
        when(metadataService.getUnsignedIssuerMetadata()).thenReturn(issuerMetadata);
        when(applicationProperties.getAcceptableProofTimeWindowSeconds()).thenReturn(60);
        when(applicationProperties.getNonceLifetimeSeconds()).thenReturn(60);

        offer = mock(CredentialOffer.class);
        management = mock(CredentialManagement.class);
        when(management.getMetadataTenantId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(offer.getCredentialManagement()).thenReturn(management);
        config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);

        holderBindingService = new HolderBindingService(
                metadataService, nonceService, keyAttestationService, applicationProperties
        );

        holderKeys = IntStream.range(0, 3).boxed().map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key-" + i)
                .issueTime(new Date())
                .generate())
        ).toList();
    }

    @Test
    void returnsEmptyListIfNoProofTypesSupported() {
        SupportedProofType proofType = new SupportedProofType();
        proofType.setSupportedSigningAlgorithms(List.of("ES256"));
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));
        when(config.getProofTypesSupported()).thenReturn(null);
        List<String> proofs = List.of("Proof1", "Proof2");

        CredentialRequestClass credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId);

        List<ProofJwt> result = holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer);
        assertTrue(result.isEmpty());
    }

    @Test
    void throwsIfNoProofsProvided() {
        SupportedProofType proofType = new SupportedProofType();
        proofType.setSupportedSigningAlgorithms(List.of("ES256"));
        Map<String, SupportedProofType> proofTypesSupported = Map.of("jwt", proofType);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));
        when(config.getProofTypesSupported()).thenReturn(proofTypesSupported);

        CredentialRequestClass credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), List.of()),
                null,
                supportedCredentialId);

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer));

        assertEquals("Proof must be provided for the requested credential", e.getMessage());
    }

    @Test
    void throwsIfMultipleProofsAndNoBatchIssuance() {
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));
        when(issuerMetadata.getBatchCredentialIssuance()).thenReturn(null);

        List<String> proofs = List.of("Proof1", "Proof2");

        CredentialRequestClass credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId);

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer));
        assertEquals("Multiple proofs are not allowed for this credential request", e.getMessage());
    }

    @Test
    void validateHolderPublicKeys_reusedProof_throwsOID4VCIException() {
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));
        mockBatchCredentialIssuance(2);

        List<String> proofs = List.of("Proof1", "Proof1");
        var proofJwt = mock(ProofJwt.class);
        when(proofJwt.getProofType()).thenReturn(ProofType.JWT);
        when(proofJwt.isValidHolderBinding(anyString(), anyList(), anyLong())).thenReturn(true);
        when(proofJwt.getBinding()).thenReturn("binding");

        holderBindingService = spy(holderBindingService);


        CredentialRequestClass credentialRequestSpy = spy(new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId));
        when(credentialRequestSpy.getProofs(anyInt(), anyInt())).thenReturn(List.of(proofJwt, proofJwt));

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.getValidateHolderPublicKeys(credentialRequestSpy, offer));
        assertEquals("Provided proof is not supported for the credential requested.", e.getMessage());
    }

    @Test
    void validateHolderPublicKeys_invalidProof_throwsOID4VCIException() {
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        var credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(
                        // CAUTION Triggers the deprecated "OpenID for Verifiable Credential Issuance - draft 15" flow
                        //         (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-8.2)
                        "proof_type", ProofType.JWT.toString()
                ),
                null,
                supportedCredentialId);

        var exc = assertThrows(Oid4vcException.class, () ->
                spy(holderBindingService).getValidateHolderPublicKeys(spy(credentialRequest), offer));
        assertEquals("Invalid proof", exc.getMessage());
    }

    @Test
    void validateHolderPublicKeys_proofNotSupported_throwsOID4VCIException() {
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        var credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(
                        // CAUTION Triggers the deprecated "OpenID for Verifiable Credential Issuance - draft 15" flow
                        //         (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-8.2)
                        "proof_type", ProofType.JWT.toString(),
                        ProofType.JWT.toString(), ProofType.JWT.toString()
                ),
                null,
                supportedCredentialId);

        var exc = assertThrows(Oid4vcException.class, () ->
                spy(holderBindingService).getValidateHolderPublicKeys(spy(credentialRequest), offer));
        assertEquals("Provided proof is not supported for the credential requested.", exc.getMessage());
    }

    @Test
    void throwsIfProofsExceedBatchSize() {
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));
        mockBatchCredentialIssuance(1);

        List<String> proofs = List.of("Proof1", "Proof2");

        CredentialRequestClass credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId);

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer));
        assertEquals("The number of proofs must be at least the same as the batch size", e.getMessage());
    }

    @Test
    void givenCorrectParams_whenGetValidateHolderPublicKeys_thenSuccess() {
        CredentialOffer offer = mock(CredentialOffer.class);
        CredentialManagement mgmt = mock(CredentialManagement.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        when(offer.getCredentialManagement()).thenReturn(mgmt);
        when(mgmt.getAccessTokenExpirationTimestamp()).thenReturn(Instant.now().plusSeconds(600).getEpochSecond());
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        SupportedProofType proofType = new SupportedProofType();
        proofType.setSupportedSigningAlgorithms(List.of("ES256"));
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("jwt", proofType));
        mockBatchCredentialIssuance(3);

        List<String> proofs = holderKeys.stream().map(holderKey -> assertDoesNotThrow(() -> TestServiceUtils.createHolderProof(holderKey,
                "did:example:issuer", UUID.randomUUID() + "::" + Instant.now().minusSeconds(1).toString(),
                ProofType.JWT.getClaimTyp(), false))).toList();

        CredentialRequestClass credentialRequest = new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId);

        assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, offer));
    }

    private void mockBatchCredentialIssuance(int batchSize) {
        var batchCredentialIssuance = new BatchCredentialIssuance(batchSize);
        when(issuerMetadata.getBatchCredentialIssuance()).thenReturn(batchCredentialIssuance);
    }
}