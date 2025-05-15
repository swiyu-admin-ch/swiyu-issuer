package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.domain.openid.metadata.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests with the example_issuer_metadata.json and testing the example configs.
 */
@SpringBootTest
class IssuerMetadataTechnicalTest {

    @Autowired
    IssuerMetadataTechnical issuerMetadataTechnical;

    private SupportedProofType getSupportedProofType(IssuerMetadataTechnical metadata, String credentialConfigurationId) {
        var credentialConfigurations = metadata.getCredentialConfigurationSupported();
        assertTrue(credentialConfigurations.containsKey(credentialConfigurationId), "Credential configuration '" + credentialConfigurationId + "' not found");
        var proofTypesSupported = credentialConfigurations.get(credentialConfigurationId).getProofTypesSupported();
        assertTrue(proofTypesSupported.containsKey("jwt"), "Proof type 'jwt' not found");
        return proofTypesSupported.get("jwt");
    }

    @Test
    void testNoKeyAttestation() throws IOException {
        var proofType = getSupportedProofType(issuerMetadataTechnical, "university_example_sd_jwt");
        assertNull(proofType.getKeyAttestationRequirement(), "When not explicitly defined in the metadata, key attestation requirement should be null");
    }

    @Test
    void testAnyKeyAttestation() throws IOException {
        var proofType = getSupportedProofType(issuerMetadataTechnical, "university_example_any_key_attestation_required_sd_jwt");
        var attestationRequirement = proofType.getKeyAttestationRequirement();
        assertNotNull(attestationRequirement, "When provided with a empty attestation shall be not null");
        assertNull(attestationRequirement.getKeyStorage(), "No definition of the key storage should exist, leaving the choice to the wallet");
    }

    @Test
    void testHighKeyAttestation() throws IOException {
        var proofType = getSupportedProofType(issuerMetadataTechnical, "university_example_high_key_attestation_required_sd_jwt");
        var attestationRequirement = proofType.getKeyAttestationRequirement();
        assertNotNull(attestationRequirement, "When provided with a empty attestation shall be not null");
        var allowedAttackPotentialResistanceOptions = attestationRequirement.getKeyStorage();
        assertNotNull(allowedAttackPotentialResistanceOptions);
        assertEquals(1, allowedAttackPotentialResistanceOptions.size());
        assertTrue(allowedAttackPotentialResistanceOptions.contains(AttackPotentialResistance.iso_18045_high));

    }
}
