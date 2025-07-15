package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.KeyAttestationService;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KeyAttestationServiceTest {

    private KeyResolver keyResolver;
    private ApplicationProperties applicationProperties;
    private KeyAttestationService keyAttestationService;

    @BeforeEach
    void setUp() {
        keyResolver = mock(KeyResolver.class);
        applicationProperties = mock(ApplicationProperties.class);
        keyAttestationService = new KeyAttestationService(keyResolver, applicationProperties);
    }

    @Test
    void checkHolderKeyAttestation_noAttestationRequired_doesNothing() {
        SupportedProofType supportedProofType = mock(SupportedProofType.class);
        when(supportedProofType.getKeyAttestationRequirement()).thenReturn(null);
        Proof proof = mock(Proof.class);

        assertDoesNotThrow(() -> keyAttestationService.checkHolderKeyAttestation(supportedProofType, proof));
    }

    @Test
    void checkHolderKeyAttestation_proofNotAttestable_throwsException() {
        SupportedProofType supportedProofType = mock(SupportedProofType.class);
        when(supportedProofType.getKeyAttestationRequirement()).thenReturn(mock(KeyAttestationRequirement.class));
        Proof proof = mock(Proof.class);

        Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                keyAttestationService.checkHolderKeyAttestation(supportedProofType, proof));

        assertTrue(ex.getMessage().contains("Attestation was requested, but presented proof is not attestable!"));
    }

    @Test
    void checkHolderKeyAttestation_attestationMissing_throwsException() {
        SupportedProofType supportedProofType = mock(SupportedProofType.class);
        when(supportedProofType.getKeyAttestationRequirement()).thenReturn(mock(KeyAttestationRequirement.class));
        ProofJwt proof = mock(ProofJwt.class);

        Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                keyAttestationService.checkHolderKeyAttestation(supportedProofType, proof));
        assertTrue(ex.getMessage().contains("Attestation was not provided"));
    }

    @Test
    void checkHolderKeyAttestation_mimi_throwsException() {
        SupportedProofType supportedProofType = mock(SupportedProofType.class);
        when(supportedProofType.getKeyAttestationRequirement()).thenReturn(mock(KeyAttestationRequirement.class));
        ProofJwt proof = mock(ProofJwt.class);
        when(proof.getAttestationJwt()).thenReturn("malformed-key-attestation-jwt");

        Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                keyAttestationService.checkHolderKeyAttestation(supportedProofType, proof));
        assertTrue(ex.getMessage().contains("Key attestation is malformed!"));
    }

    @Test
    void throwIfInvalidAttestation_validAttestation_doesNotThrow() throws Exception {
        KeyAttestationRequirement requirement = mock(KeyAttestationRequirement.class);
        when(requirement.getKeyStorage()).thenReturn(List.of(AttackPotentialResistance.ISO_18045_HIGH));
        String jwt = "jwt";
        AttestationJwt attestationJwt = mock(AttestationJwt.class);

        try (MockedStatic<AttestationJwt> staticMock = mockStatic(AttestationJwt.class)) {
            staticMock.when(() -> AttestationJwt.parseJwt(jwt)).thenReturn(attestationJwt);
            when(applicationProperties.getTrustedAttestationProviders()).thenReturn(Collections.emptyList());
            when(attestationJwt.isValidAttestation(keyResolver, List.of(AttackPotentialResistance.ISO_18045_HIGH))).thenReturn(true);
            assertDoesNotThrow(() -> keyAttestationService.throwIfInvalidAttestation(requirement, jwt));
        }
    }

    @Test
    void throwIfInvalidAttestation_untrustedProvider_throwsException() {
        KeyAttestationRequirement requirement = mock(KeyAttestationRequirement.class);
        when(requirement.getKeyStorage()).thenReturn(List.of(AttackPotentialResistance.ISO_18045_HIGH));
        String jwt = "jwt";
        AttestationJwt attestationJwt = mock(AttestationJwt.class);

        try (MockedStatic<AttestationJwt> staticMock = mockStatic(AttestationJwt.class)) {
            staticMock.when(() -> AttestationJwt.parseJwt(jwt)).thenReturn(attestationJwt);
            when(applicationProperties.getTrustedAttestationProviders()).thenReturn(List.of("trusted"));
            doThrow(new IllegalArgumentException("untrusted")).when(attestationJwt).throwIfNotTrustedAttestationProvider(anyList());

            Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                    keyAttestationService.throwIfInvalidAttestation(requirement, jwt));
            assertTrue(ex.getMessage().contains("Attestation has been rejected"));
        }
    }

    @Test
    void throwIfInvalidAttestation_invalidAttestation_throwsException() throws Exception {
        KeyAttestationRequirement requirement = mock(KeyAttestationRequirement.class);
        when(requirement.getKeyStorage()).thenReturn(List.of(AttackPotentialResistance.ISO_18045_HIGH));
        String jwt = "jwt";
        AttestationJwt attestationJwt = mock(AttestationJwt.class);

        try (MockedStatic<AttestationJwt> staticMock = mockStatic(AttestationJwt.class)) {
            staticMock.when(() -> AttestationJwt.parseJwt(jwt)).thenReturn(attestationJwt);
            when(applicationProperties.getTrustedAttestationProviders()).thenReturn(Collections.emptyList());
            when(attestationJwt.isValidAttestation(keyResolver, List.of(AttackPotentialResistance.ISO_18045_HIGH))).thenReturn(false);

            Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                    keyAttestationService.throwIfInvalidAttestation(requirement, jwt));
            assertTrue(ex.getMessage().contains("Key attestation was invalid or not matching the attack resistance for the credential!"));
        }
    }

    @Test
    void throwIfInvalidAttestation_parseException_throwsException() {
        KeyAttestationRequirement requirement = mock(KeyAttestationRequirement.class);
        String jwt = "jwt";

        try (MockedStatic<AttestationJwt> staticMock = mockStatic(AttestationJwt.class)) {
            staticMock.when(() -> AttestationJwt.parseJwt(jwt)).thenThrow(new ParseException("ParseException", 0));

            when(applicationProperties.getTrustedAttestationProviders()).thenReturn(Collections.emptyList());

            Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                    keyAttestationService.throwIfInvalidAttestation(requirement, jwt));
            assertTrue(ex.getMessage().contains("Key attestation is malformed!"));
        }
    }

    @Test
    void throwIfInvalidAttestation_joseException_throwsException() throws JOSEException {
        KeyAttestationRequirement requirement = mock(KeyAttestationRequirement.class);
        String jwt = "jwt";
        AttestationJwt attestationJwt = mock(AttestationJwt.class);
        try (MockedStatic<AttestationJwt> staticMock = mockStatic(AttestationJwt.class)) {
            staticMock.when(() -> AttestationJwt.parseJwt(jwt)).thenReturn(attestationJwt);
            when(attestationJwt.isValidAttestation(any(), any())).thenThrow(new JOSEException("JOSEException"));
            when(applicationProperties.getTrustedAttestationProviders()).thenReturn(Collections.emptyList());

            Oid4vcException ex = assertThrows(Oid4vcException.class, () ->
                    keyAttestationService.throwIfInvalidAttestation(requirement, jwt));
            assertTrue(ex.getMessage().contains("not supported"));
        }
    }
}