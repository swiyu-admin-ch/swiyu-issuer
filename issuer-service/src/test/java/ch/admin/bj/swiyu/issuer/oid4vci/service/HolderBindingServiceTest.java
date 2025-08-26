package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.BatchCredentialIssuance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.HolderBindingService;
import ch.admin.bj.swiyu.issuer.service.KeyAttestationService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class HolderBindingServiceTest {

    private final String supportedCredentialId = "this-is-a-supported-credential-id";
    private IssuerMetadataTechnical issuerMetadata;
    private NonceService nonceService;
    private HolderBindingService holderBindingService;

    @BeforeEach
    void setUp() {
        issuerMetadata = mock(IssuerMetadataTechnical.class);
        OpenIdIssuerConfiguration openIdIssuerConfiguration = mock(OpenIdIssuerConfiguration.class);
        nonceService = mock(NonceService.class);
        KeyAttestationService keyAttestationService = mock(KeyAttestationService.class);
        ApplicationProperties applicationProperties = mock(ApplicationProperties.class);
        holderBindingService = new HolderBindingService(
                issuerMetadata, openIdIssuerConfiguration, nonceService, keyAttestationService, applicationProperties
        );
    }

    @Test
    void returnsEmptyListIfNoProofTypesSupported() {
        SupportedProofType proofType = new SupportedProofType();
        proofType.setSupportedSigningAlgorithms(List.of("ES256"));
        CredentialOffer offer = mock(CredentialOffer.class);
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));

        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        CredentialOffer offer = mock(CredentialOffer.class);
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));

        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of(supportedCredentialId));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));
        mockBatchCredentialIssuance(2);

        List<String> proofs = List.of("Proof1", "Proof1");
        var proofJwt = mock(ProofJwt.class);
        when(proofJwt.getProofType()).thenReturn(ProofType.JWT);
        when(proofJwt.isValidHolderBinding(anyString(), anyList(), any(), anyLong())).thenReturn(true);
        when(proofJwt.getBinding()).thenReturn("binding");

        holderBindingService = spy(holderBindingService);

        doReturn(proofJwt).when(holderBindingService).validateHolderPublicKeyV2(any(), any(), any());

        CredentialRequestClass credentialRequestSpy = spy(new CredentialRequestClass(
                SD_JWT_FORMAT,
                Map.of(ProofType.JWT.toString(), proofs),
                null,
                supportedCredentialId));
        when(credentialRequestSpy.getProofs(anyInt(), anyInt())).thenReturn(List.of(proofJwt, proofJwt));

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.getValidateHolderPublicKeys(credentialRequestSpy, offer));
        assertEquals("Proofs should not be duplicated for the same credential request", e.getMessage());
    }


    @Test
    void throwsIfProofsExceedBatchSize() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        assertEquals("The number of proofs exceeds the batch size limit", e.getMessage());
    }

    @Test
    void validateHolderPublicKeyV2_thenException() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        SupportedProofType supportedProofType = mock(SupportedProofType.class);

        Optional<ProofJwt> proof = Optional.empty();
        var supportedProofTypes = Map.of("type", supportedProofType);
        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.validateHolderPublicKeyV2(proof, offer, supportedProofTypes));
        assertEquals("Proof must be provided for the requested credential", e.getMessage());
    }

    @Test
    void validateHolderPublicKeyV2_unsupportedProofType_thenException() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        Map<String, SupportedProofType> supportedProofTypes = mock(Map.class);
        when(supportedProofTypes.get(anyString())).thenReturn(null);

        var proofJwt = Optional.of(new ProofJwt(ProofType.JWT, "proof", 100, 100));

        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.validateHolderPublicKeyV2(proofJwt, offer, supportedProofTypes));
        assertEquals("Provided proof is not supported for the credential requested.", e.getMessage());
    }


    @Test
    void validateHolderPublicKeyV2_isValidHolderBindingFails_thenException() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        Map<String, SupportedProofType> supportedProofTypes = mock(Map.class);
        var supportedProofType = new SupportedProofType();
        supportedProofType.setSupportedSigningAlgorithms(List.of("ES256"));

        when(supportedProofTypes.get("type")).thenReturn(supportedProofType);
        when(supportedProofTypes.get(any())).thenReturn(supportedProofType);

        ProofJwt proofJwt = mock(ProofJwt.class);
        when(proofJwt.getProofType()).thenReturn(ProofType.JWT);
        when(proofJwt.isValidHolderBinding(anyString(), anyList(), any(), anyLong())).thenReturn(false);

        var proofJwtOptional = Optional.of(proofJwt);
        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.validateHolderPublicKeyV2(proofJwtOptional, offer, supportedProofTypes));
        assertEquals("Presented proof was invalid!", e.getMessage());
    }

    @Test
    void validateHolderPublicKeyV2_reusedNonce_thenException() {
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
        when(config.getProofTypesSupported()).thenReturn(Map.of("type", mock(SupportedProofType.class)));

        Map<String, SupportedProofType> supportedProofTypes = mock(Map.class);
        var supportedProofType = new SupportedProofType();
        supportedProofType.setSupportedSigningAlgorithms(List.of("ES256"));

        when(supportedProofTypes.get("type")).thenReturn(supportedProofType);
        when(supportedProofTypes.get(any())).thenReturn(supportedProofType);

        ProofJwt proofJwt = mock(ProofJwt.class);
        when(proofJwt.getProofType()).thenReturn(ProofType.JWT);
        when(proofJwt.getNonce()).thenReturn("self-contained::nonce");
        when(proofJwt.isValidHolderBinding(any(), anyList(), any(), any())).thenReturn(true);

        when(nonceService.isUsedNonce(any(SelfContainedNonce.class))).thenReturn(true);

        var proofJwtOptional = Optional.of(proofJwt);
        var e = assertThrows(Oid4vcException.class, () ->
                holderBindingService.validateHolderPublicKeyV2(proofJwtOptional, offer, supportedProofTypes));
        assertEquals("Presented proof was reused!", e.getMessage());
    }

    private void mockBatchCredentialIssuance(int batchSize) {
        var batchCredentialIssuance = new BatchCredentialIssuance(batchSize);
        when(issuerMetadata.getBatchCredentialIssuance()).thenReturn(batchCredentialIssuance);
    }
}