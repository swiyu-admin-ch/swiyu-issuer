package ch.admin.bj.swiyu.issuer.oid4vci;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests with the example_issuer_metadata.json and testing the example configs.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles({"test", "signed-metadata"})
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class IssuerMetadataIT {

    @Autowired
    IssuerMetadata issuerMetadata;

    private SupportedProofType getSupportedProofType(IssuerMetadata metadata, String credentialConfigurationId) {
        var credentialConfigurations = metadata.getCredentialConfigurationSupported();
        assertTrue(credentialConfigurations.containsKey(credentialConfigurationId), "Credential configuration '" + credentialConfigurationId + "' not found");
        var proofTypesSupported = credentialConfigurations.get(credentialConfigurationId).getProofTypesSupported();
        assertTrue(proofTypesSupported.containsKey("jwt"), "Proof type 'jwt' not found");
        return proofTypesSupported.get("jwt");
    }

    @Test
    void testNoKeyAttestation() {
        var proofType = getSupportedProofType(issuerMetadata, "university_example_sd_jwt");
        assertNull(proofType.getKeyAttestationRequirement(), "When not explicitly defined in the metadata, key attestation requirement should be null");
    }

    @Test
    void testAnyKeyAttestation() {
        var proofType = getSupportedProofType(issuerMetadata, "university_example_any_key_attestation_required_sd_jwt");
        var attestationRequirement = proofType.getKeyAttestationRequirement();
        assertNotNull(attestationRequirement, "When provided with a empty attestation shall be not null");
        assertTrue(attestationRequirement.getKeyStorage().isEmpty(), "No definition of the key storage should exist, leaving the choice to the wallet");
    }

    @Test
    void testHighKeyAttestation() {
        var proofType = getSupportedProofType(issuerMetadata, "university_example_high_key_attestation_required_sd_jwt");
        var attestationRequirement = proofType.getKeyAttestationRequirement();
        assertNotNull(attestationRequirement, "When provided with a empty attestation shall be not null");
        var allowedAttackPotentialResistanceOptions = attestationRequirement.getKeyStorage();
        assertNotNull(allowedAttackPotentialResistanceOptions);
        assertEquals(1, allowedAttackPotentialResistanceOptions.size());
        assertTrue(allowedAttackPotentialResistanceOptions.contains(AttackPotentialResistance.ISO_18045_HIGH));

    }
}