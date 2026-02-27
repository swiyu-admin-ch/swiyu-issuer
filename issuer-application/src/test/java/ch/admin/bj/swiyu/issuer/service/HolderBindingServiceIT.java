package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.ProofsDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.credential.HolderBindingService;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.credential.CredentialRequestMapper.toCredentialRequest;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class HolderBindingServiceIT {
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @Autowired
    private HolderBindingService holderBindingService;
    @MockitoBean
    private DidKeyResolverFacade didKeyResolver;

    private ECKey attestationKey;

    private static CredentialOffer createHolderBindingTestOffer() {
        var credentialManagement = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build();

        var offer = CredentialOffer.builder()
                .metadataCredentialSupportedId(List.of("university_example_any_key_attestation_required_sd_jwt"))
                .offerData(Map.of())
                .nonce(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .credentialManagement(credentialManagement)
                .build();

        credentialManagement.addCredentialOffer(offer);
        return offer;
    }

    @BeforeEach
    void setUp() throws JOSEException {
        attestationKey = new ECKeyGenerator(Curve.P_256).keyID("did:test:test-attestation-builder#key-1").keyUse(KeyUse.SIGNATURE).generate();
        Mockito.when(didKeyResolver.resolveKey(Mockito.any())).thenReturn(attestationKey);
    }

    @Test
    void correctHolderBindings_uniqueNonces_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        assertThat(issuerMetadata.getIssuanceBatchSize()).as("Test Configuration must have batch issuance for this test").isGreaterThan(1);
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String nonce = new SelfContainedNonce().getNonce();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");
    }

    @Test
    void correctHolderBindings_sameNonce_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        String nonce = new SelfContainedNonce().getNonce();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");
    }

    @Deprecated(since = "OID4VCI 1.0")
    @Test
    void mixedNonces_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        var deprecatedNonce = credentialOffer.getNonce().toString();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            String nonce;
            if (i % 2 == 0) {
                nonce = new SelfContainedNonce().getNonce();
            } else {
                nonce = deprecatedNonce;
            }

            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");

        // Should also throw if the self contained nonces are done anew
        proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            String nonce;
            if (i % 2 == 0) {
                nonce = new SelfContainedNonce().getNonce();
            } else {
                nonce = deprecatedNonce;
            }

            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequestReusedDeprecatedNonce = toCredentialRequest(request);

        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequestReusedDeprecatedNonce, credentialOffer), "Should also throw if the self contained nonces are done anew");
    }

    /**
     * EIDSEC-633
     * An invalid nonce passes all checks but then is not registered to the server for future replay attack checks.
     * This can lead to a complete bypass of replay prevention, which is the entire point of nonces.
     * </br>
     * <em>Problem</em>: During validation of the nonce for holder binding,
     * as well as DPoP there is an issue where a invalid nonce (one that does not contain "::")
     * is accepted (without any errors) but not added to the database.
     * This effectively removes the whole replay protection of both DPoP and holder binding.
     */
    @Deprecated(since = "OID4VCI 1.0")
    @Test
    void mixedNonces_whenInvalidNoncePresent_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            String nonce;
            if (i % 2 == 0) {
                nonce = new SelfContainedNonce().getNonce();
            } else {
                nonce = UUID.randomUUID().toString();
            }

            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Should not be accepted");
    }

    @Test
    void whenMissingHolderBinding_thenOid4vcException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            String nonce = null;
            if (i == 0) {
                nonce = new SelfContainedNonce().getNonce();
            } else {
                nonce = "";
            }
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Missing nonce in proofs shall not be accepted");
    }

    @Test
    void whenUnregisteredNonce_thenOid4vcException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    UUID.randomUUID().toString(),
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Unknown non-self-contained nonces should be refused");
    }

    /**
     * EIDSEC-632
     */
    @Deprecated(since = "OID4VCI 1.0")
    @Test
    void whenRegisteredNonce_thenSuccess_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    credentialOffer.getNonce().toString(),
                    ProofType.JWT.getClaimTyp(),
                    true,
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CredentialEndpointRequestDto request = new CredentialEndpointRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");
    }

}