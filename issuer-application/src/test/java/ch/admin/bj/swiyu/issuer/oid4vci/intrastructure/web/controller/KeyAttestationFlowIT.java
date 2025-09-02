package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.DidKeyResolverApiClient;
import ch.admin.bj.swiyu.issuer.service.DidTdwKeyResolver;
import ch.admin.bj.swiyu.issuer.service.webhook.WebhookService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.prepareAttestedVC;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class KeyAttestationFlowIT {
    private static ECKey jwk;
    private final UUID testOfferNoAttestationId = UUID.randomUUID();
    private final UUID testOfferAnyAttestationId = UUID.randomUUID();
    private final UUID testOfferHighAttestationId = UUID.randomUUID();
    @MockitoBean
    DidTdwKeyResolver resolver;

    @Autowired
    MockMvc mock;

    @Autowired
    CredentialOfferRepository credentialOfferRepository;

    @Autowired
    ApplicationProperties applicationProperties;
    @Autowired
    private DidTdwKeyResolver didTdwKeyResolver;
    @Autowired
    private DidKeyResolverApiClient didKeyResolverApiClient;

    @MockitoSpyBean
    private WebhookService webhookService;

    private CredentialOffer credentialOfferHighAttestation;
    private CredentialOffer credentialOfferAnyAttestation;

    @BeforeEach
    void setUp() throws JOSEException {
        credentialOfferRepository.save(createTestOffer(testOfferNoAttestationId, CredentialStatusType.OFFERED, "university_example_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        credentialOfferAnyAttestation = credentialOfferRepository.save(createTestOffer(testOfferAnyAttestationId, CredentialStatusType.OFFERED, "university_example_any_key_attestation_required_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        credentialOfferHighAttestation = credentialOfferRepository.save(createTestOffer(testOfferHighAttestationId, CredentialStatusType.OFFERED, "university_example_high_key_attestation_required_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        jwk = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID("Test-Key").issueTime(new Date()).generate();
    }

    /**
     * We ask for any form of attestation. So we should accept any.
     */
    @ParameterizedTest
    @EnumSource(value = AttackPotentialResistance.class)
    void testAnyKeyAttestationFlow(AttackPotentialResistance resistance) throws Exception {
        var fetchData = prepareAttested(mock, testOfferAnyAttestationId, resistance);
        mockDidResolve(jwk.toPublicJWK());
        var result = TestInfrastructureUtils.getCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        assertNotNull(result);
    }

    @Test
    void testSuperfluousAttestation() throws Exception {
        var fetchData = prepareAttested(mock, testOfferNoAttestationId, AttackPotentialResistance.ISO_18045_ENHANCED_BASIC);
        mockDidResolve(jwk.toPublicJWK());
        var result = TestInfrastructureUtils.getCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        assertNotNull(result);
    }

    @Test
    void testHighAttestation() throws Exception {
        var fetchData = prepareAttested(mock, testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_HIGH);
        mockDidResolve(jwk.toPublicJWK());
        var result = TestInfrastructureUtils.getCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        assertNotNull(result);

        verify(webhookService, Mockito.times(1)).produceStateChangeEvent(credentialOfferHighAttestation.getId(), CredentialStatusType.IN_PROGRESS);
    }

    /**
     * Test Requesting the highest possible attestation. Any lower provided attestation MUST fail
     */
    @ParameterizedTest
    @EnumSource(value = AttackPotentialResistance.class, mode = EnumSource.Mode.EXCLUDE, names = {"ISO_18045_HIGH"})
    void testTooLowAttestation_thenFail(AttackPotentialResistance resistance) throws Exception {
        var fetchData = prepareAttested(mock, testOfferHighAttestationId, resistance);
        mockDidResolve(jwk.toPublicJWK());
        var response = TestInfrastructureUtils.requestFailingCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Key attestation");

        verify(webhookService, Mockito.times(1)).produceErrorEvent(credentialOfferHighAttestation.getId(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, "Key attestation was invalid or not matching the attack resistance for the credential!");
    }

    @Test
    void testUntrustedAttestationIssuer() throws Exception {
        var untrustedIssuer = "did:example:untrusted";
        var fetchData = prepareAttestedVC(mock, testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_HIGH, untrustedIssuer, jwk, applicationProperties.getTemplateReplacement().get("external-url"));
        mockDidResolve(jwk.toPublicJWK());
        var response = TestInfrastructureUtils.requestFailingCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        // Proof should be invalid when untrusted
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        // We want the error description to be helpful telling about the current issuer and the expected issuers.
        Assertions.assertThat(response.get("error_description").getAsString()).contains(untrustedIssuer).contains(applicationProperties.getTrustedAttestationProviders().getFirst());

        verify(webhookService, Mockito.times(1)).produceErrorEvent(credentialOfferHighAttestation.getId(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, "Attestation has been rejected! The JWT issuer did:example:untrusted is not in the list of trusted issuers did:test:test-attestation-builder.");
    }

    @Test
    void testMissingAttestation_thenFail() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, testOfferAnyAttestationId.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        var response = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Attestation");

        verify(webhookService, Mockito.times(1)).produceErrorEvent(credentialOfferAnyAttestation.getId(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, "Attestation was not provided!");
    }

    @Test
    void testInvalidAttestationSignature_thenFail() throws Exception {
        var fetchData = prepareAttested(mock, testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_ENHANCED_BASIC);
        mockDidResolve(new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID("Test-Key").issueTime(new Date()).generate().toPublicJWK());
        var response = TestInfrastructureUtils.requestFailingCredential(mock, fetchData.token(), fetchData.credentialRequestString());
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Key attestation");

        verify(webhookService, Mockito.times(1)).produceErrorEvent(credentialOfferHighAttestation.getId(), CallbackErrorEventTypeDto.KEY_BINDING_ERROR, "Key attestation key is not supported or not matching the signature!");
    }

    private void mockDidResolve(JWK key) {
        Mockito.when(didTdwKeyResolver.resolveKey(Mockito.any())).thenReturn(key);
    }

    private TestInfrastructureUtils.CredentialFetchData prepareAttested(MockMvc mock, UUID preAuthCode, AttackPotentialResistance resistance) throws Exception {
        return prepareAttestedVC(mock, preAuthCode, resistance, null, jwk, applicationProperties.getTemplateReplacement().get("external-url"));
    }
}