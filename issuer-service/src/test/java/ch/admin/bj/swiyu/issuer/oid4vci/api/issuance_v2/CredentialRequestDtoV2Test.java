package ch.admin.bj.swiyu.issuer.oid4vci.api.issuance_v2;


import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialRequestDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.ProofsDto;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CredentialRequestDtoV2Test {

    @Test
    void shouldCreateDtoWithAllFields() {
        ProofsDto proofs = new ProofsDto(List.of("jwt"));

        CredentialRequestDtoV2 dto = new CredentialRequestDtoV2("config-id", proofs, null);

        assertEquals("config-id", dto.credentialConfigurationId());
        assertSame(proofs, dto.proofs());
        assertSame(null, dto.credentialResponseEncryption());
    }

    @Test
    void shouldFailValidationIfCredentialConfigurationIdBlank() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var credentialRequestDtoV2 = new CredentialRequestDtoV2(" ", null, null);
            var violations = validator.validate(credentialRequestDtoV2);

            assertFalse(violations.isEmpty());
            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("credentialConfigurationId")));
        }
    }
}