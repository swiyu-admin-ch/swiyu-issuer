package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HolderBindingServiceTest {

    private final String supportedCredentialId = "this-is-a-supported-credential-id";
    private IssuerMetadata issuerMetadata;
    private NonceService nonceService;
    private HolderBindingService holderBindingService;

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

        holderBindingService = new HolderBindingService(
                metadataService, nonceService, keyAttestationService, applicationProperties
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
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("this-is-a-supported-credential-id"));
        CredentialConfiguration config = mock(CredentialConfiguration.class);
        when(issuerMetadata.getCredentialConfigurationById(any())).thenReturn(config);
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
        assertEquals("The number of proofs must be at least the same as the batch size", e.getMessage());
    }


    private void mockBatchCredentialIssuance(int batchSize) {
        var batchCredentialIssuance = new BatchCredentialIssuance(batchSize);
        when(issuerMetadata.getBatchCredentialIssuance()).thenReturn(batchCredentialIssuance);
    }
}