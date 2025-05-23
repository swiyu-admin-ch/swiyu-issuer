package ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestUtils;
import ch.admin.bj.swiyu.issuer.service.DidTdwKeyResolver;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;

@SpringBootTest
@AutoConfigureMockMvc
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

    @BeforeEach
    void setUp() throws JOSEException {
        credentialOfferRepository.save(createTestOffer(testOfferNoAttestationId, CredentialStatusType.OFFERED, "university_example_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        credentialOfferRepository.save(createTestOffer(testOfferAnyAttestationId, CredentialStatusType.OFFERED, "university_example_any_key_attestation_required_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        credentialOfferRepository.save(createTestOffer(testOfferHighAttestationId, CredentialStatusType.OFFERED, "university_example_high_key_attestation_required_sd_jwt", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS)));
        jwk = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID("Test-Key").issueTime(new Date()).generate();
    }


    /**
     * We ask for any form of attestation. So we should accept any.
     */
    @ParameterizedTest
    @EnumSource(value = AttackPotentialResistance.class)
    void testAnyKeyAttestationFlow(AttackPotentialResistance resistance) throws Exception {
        var fetchData = prepareAttestedVC(testOfferAnyAttestationId, resistance);
        mockDidResolve(jwk.toPublicJWK());
        TestUtils.getCredential(mock, fetchData.token, fetchData.credentialRequestString);
    }

    @Test
    void testSuperfluousAttestation() throws Exception {
        var fetchData = prepareAttestedVC(testOfferNoAttestationId, AttackPotentialResistance.ISO_18045_ENHANCED_BASIC);
        mockDidResolve(jwk.toPublicJWK());
        TestUtils.getCredential(mock, fetchData.token, fetchData.credentialRequestString);
    }

    @Test
    void testHighAttestation() throws Exception {
        var fetchData = prepareAttestedVC(testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_HIGH);
        mockDidResolve(jwk.toPublicJWK());
        TestUtils.getCredential(mock, fetchData.token, fetchData.credentialRequestString);
    }

    /**
     * Test Requesting the highest possible attestation. Any lower provided attestation MUST fail
     */
    @ParameterizedTest
    @EnumSource(value = AttackPotentialResistance.class, mode = EnumSource.Mode.EXCLUDE, names = {"ISO_18045_HIGH"})
    void testTooLowAttestation_thenFail(AttackPotentialResistance resistance) throws Exception {
        var fetchData = prepareAttestedVC(testOfferHighAttestationId, resistance);
        mockDidResolve(jwk.toPublicJWK());
        var response = TestUtils.requestFailingCredential(mock, fetchData.token, fetchData.credentialRequestString);
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Attestation");
    }

    @Test
    void testUntrustedAttestationIssuer() throws Exception {
        var untrustedIssuer = "did:example:untrusted";
        var fetchData = prepareAttestedVC(testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_HIGH, untrustedIssuer);
        mockDidResolve(jwk.toPublicJWK());
        var response = TestUtils.requestFailingCredential(mock, fetchData.token, fetchData.credentialRequestString);
        // Proof should be invalid when untrusted
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        // We want the error description to be helpful telling about the current issuer and the expected issuers.
        Assertions.assertThat(response.get("error_description").getAsString()).contains(untrustedIssuer).contains(applicationProperties.getTrustedAttestationProviders().getFirst());
    }

    @Test
    void testMissingAttestation_thenFail() throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, testOfferAnyAttestationId.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        var response = TestUtils.requestFailingCredential(mock, token, credentialRequestString);
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Attestation");
    }

    @Test
    void testInvalidAttestationSignature_thenFail() throws Exception {
        var fetchData = prepareAttestedVC(testOfferHighAttestationId, AttackPotentialResistance.ISO_18045_ENHANCED_BASIC);
        mockDidResolve(new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID("Test-Key").issueTime(new Date()).generate().toPublicJWK());
        var response = TestUtils.requestFailingCredential(mock, fetchData.token, fetchData.credentialRequestString);
        Assertions.assertThat(response.get("error").getAsString()).hasToString(CredentialRequestErrorDto.INVALID_PROOF.name());
        Assertions.assertThat(response.get("error_description").getAsString()).contains("Attestation");
    }


    private CredentialFetchData prepareAttestedVC(UUID offerId, AttackPotentialResistance resistance) throws Exception {
        return prepareAttestedVC(offerId, resistance, null);
    }
    private CredentialFetchData prepareAttestedVC(UUID offerId, AttackPotentialResistance resistance, String attestationIssuerDid) throws Exception {
        var tokenResponse = TestUtils.fetchOAuthToken(mock, offerId.toString());
        var token = tokenResponse.get("access_token");
        Assertions.assertThat(token).isNotNull();
        Assertions.assertThat(tokenResponse).containsKey("c_nonce");
        String proof = TestUtils.createAttestedHolderProof(
                jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                tokenResponse.get("c_nonce").toString(),
                ProofType.JWT.getClaimTyp(),
                false,
                resistance,
                attestationIssuerDid);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);

        return new CredentialFetchData(token, credentialRequestString);
    }

    private void mockDidResolve(JWK key) {
        Mockito.when(didTdwKeyResolver.resolveKey(Mockito.any())).thenReturn(key);
    }

    record CredentialFetchData(Object token, String credentialRequestString) {
    }

}
