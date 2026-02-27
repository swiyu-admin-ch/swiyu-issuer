package ch.admin.bj.swiyu.issuer.dto.issuance_v2;


import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.ProofsDto;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class CredentialRequestDtoV2Test {

    @Test
    void shouldCreateDtoWithAllFields() {
        ProofsDto proofs = new ProofsDto(List.of("jwt"));

        CredentialEndpointRequestDto dto = new CredentialEndpointRequestDto("config-id", proofs, null);

        assertEquals("config-id", dto.credentialConfigurationId());
        assertSame(proofs, dto.proofs());
        assertSame(null, dto.credentialResponseEncryption());
    }

    @Test
    void shouldFailValidationIfCredentialConfigurationIdBlank() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var credentialRequestDtoV2 = new CredentialEndpointRequestDto(" ", null, null);
            var violations = validator.validate(credentialRequestDtoV2);

            assertThat(violations).isNotEmpty();
            assertThat(violations.stream().map(v -> v.getPropertyPath().toString()).toList()).contains("credentialConfigurationId");
        }
    }
}