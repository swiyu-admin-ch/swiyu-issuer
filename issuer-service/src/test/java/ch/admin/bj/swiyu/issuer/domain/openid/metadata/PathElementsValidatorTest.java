package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PathElementsValidatorTest {

    @Test
    void pathElementsValidator_validPath_acceptsStringsNullsAndNonNegativeIntegers() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var bean = new TestBean(Arrays.asList("a", null, 0, 1L, new BigInteger("3"), new BigDecimal("4"), 5.0d));

            var violations = validator.validate(bean);
            assertTrue(violations.isEmpty(), "Expected no validation violations for a valid path list");
        }
    }

    @Test
    void pathElementsValidator_emptyList_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var bean = new TestBean(List.of());

            var violations = validator.validate(bean);
            assertFalse(violations.isEmpty());
            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("path")));
        }
    }

    @Test
    void pathElementsValidator_negativeInteger_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var bean = new TestBean(List.of(-1));

            var violations = validator.validate(bean);
            assertFalse(violations.isEmpty());
        }
    }

    @Test
    void pathElementsValidator_fractionalNumber_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var bean = new TestBean(List.of(1.5));

            var violations = validator.validate(bean);
            assertFalse(violations.isEmpty());
        }
    }

    @Test
    void pathElementsValidator_nonStringNonNumberObject_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var bean = new TestBean(List.of(new Object()));

            var violations = validator.validate(bean);
            assertFalse(violations.isEmpty());
        }
    }

    @Test
    void pathElementsValidator_nanAndInfinity_failsValidation() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            var beanNaN = new TestBean(List.of(Double.NaN));
            var beanInf = new TestBean(List.of(Double.POSITIVE_INFINITY));

            assertFalse(validator.validate(beanNaN).isEmpty());
            assertFalse(validator.validate(beanInf).isEmpty());
        }
    }

    static class TestBean {
        @ValidPathElements
        List<Object> path;

        TestBean(List<Object> path) {
            this.path = path;
        }
    }
}