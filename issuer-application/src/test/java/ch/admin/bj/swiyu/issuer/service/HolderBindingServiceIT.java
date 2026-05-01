package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.ProofsDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecret;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecretRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.credential.HolderBindingService;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.eid.did_sidekicks.DidDoc;
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
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
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

    /** A real did:tdw DID accepted by DidKidParser (used as attestation issuer DID). */
    private static final String ATTESTATION_ISSUER_DID = "did:tdw:QmWrXWFEDenvoYWFXxSQGFCa6Pi22Cdsg2r6weGhY2ChiQ:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:2e246676-209a-4c21-aceb-721f8a90b212";

    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @Autowired
    private HolderBindingService holderBindingService;
    @Autowired
    private IssuerSecretRepository nonceSecretRepository;
    @MockitoBean
    private DidKeyResolverFacade didKeyResolver;
    @MockitoBean
    private DidJwtValidator didJwtValidator;
    @MockitoBean
    private DidResolverAdapter didResolverAdapter;

    private IssuerSecret nonceSecret;
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
                .preAuthorizedCode(UUID.randomUUID())
                .credentialManagement(credentialManagement)
                .build();

        credentialManagement.addCredentialOffer(offer);
        return offer;
    }

    @BeforeEach
    void setUp() throws JOSEException {
        attestationKey = new ECKeyGenerator(Curve.P_256).keyID(ATTESTATION_ISSUER_DID + "#key-1").keyUse(KeyUse.SIGNATURE).generate();
        Mockito.when(didKeyResolver.resolveKey(Mockito.any())).thenReturn(attestationKey);
        // Bypass DID resolution for test attestation DIDs – real DID validation is covered by KeyAttestationServiceTest
        Mockito.doReturn("https://identifier-reg.trust-infra.swiyu-int.admin.ch/test").when(didJwtValidator).getAndValidateResolutionUrl(Mockito.any());
        Mockito.doReturn(ATTESTATION_ISSUER_DID).when(didJwtValidator).getDidString(Mockito.any());
        Mockito.doNothing().when(didJwtValidator).validateJwt(Mockito.any(String.class), Mockito.any(DidDoc.class));
        DidDoc mockDidDoc = Mockito.mock(DidDoc.class);
        Mockito.doReturn(mockDidDoc).when(didResolverAdapter).resolveDid(Mockito.any(), Mockito.any());
        nonceSecret = nonceSecretRepository.findAll().getFirst();
    }

    @Test
    void correctHolderBindings_uniqueNonces_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        assertThat(issuerMetadata.getIssuanceBatchSize()).as("Test Configuration must have batch issuance for this test").isGreaterThan(1);
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String nonce = new SelfContainedNonce(nonceSecret).getNonce();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
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
        String nonce = new SelfContainedNonce(nonceSecret).getNonce();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");
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
    @Test
    void mixedNonces_whenInvalidNoncePresent_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            String nonce;
            if (i % 2 == 0) {
                nonce = new SelfContainedNonce(nonceSecret).getNonce();
            } else {
                nonce = UUID.randomUUID().toString();
            }

            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
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
                nonce = new SelfContainedNonce(nonceSecret).getNonce();
            } else {
                nonce = "";
            }
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
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
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
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
    @Test
    void whenRegisteredNonce_thenSuccess_whenReplayed_thenOid4vciException() throws JOSEException {
        var credentialOffer = createHolderBindingTestOffer();
        String nonce = new SelfContainedNonce(nonceSecret).getNonce();
        List<String> proofs = new LinkedList<>();
        for (int i = 0; i < issuerMetadata.getIssuanceBatchSize(); i++) {
            ECKey proofKey = new ECKeyGenerator(Curve.P_256).keyID("Test-Key-%s".formatted(i)).keyUse(KeyUse.SIGNATURE).generate();
            String proof = TestServiceUtils.createAttestedHolderProof(
                    proofKey,
                    applicationProperties.getTemplateReplacement().get("external-url"),
                    nonce,
                    ProofType.JWT.getClaimTyp(),
                    AttackPotentialResistance.ISO_18045_ENHANCED_BASIC,
                    applicationProperties.getTrustedAttestationProviders().getFirst(),
                    attestationKey);
            proofs.add(proof);
        }
        CreateCredentialRequestDto request = new CreateCredentialRequestDto(
                credentialOffer.getMetadataCredentialSupportedId().getFirst(),
                new ProofsDto(proofs),
                null
        );
        CredentialRequestClass credentialRequest = toCredentialRequest(request);

        Assertions.assertDoesNotThrow(() -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Initial validation must succeed");
        Assertions.assertThrows(Oid4vcException.class, () -> holderBindingService.getValidateHolderPublicKeys(credentialRequest, credentialOffer), "Second Validation must fail, as nonces were reused");
    }

}