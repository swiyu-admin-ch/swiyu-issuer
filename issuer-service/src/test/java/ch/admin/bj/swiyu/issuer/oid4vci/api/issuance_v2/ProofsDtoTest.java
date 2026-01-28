package ch.admin.bj.swiyu.issuer.oid4vci.api.issuance_v2;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance_v2.ProofsDto;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProofsDtoTest {

    @Test
    void proofsDto_jwtListIsEmpty_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var proofsDto = new ProofsDto(List.of());
            var violations = validator.validate(proofsDto);

            assertFalse(violations.isEmpty());
            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("jwt")));
        }
    }
}