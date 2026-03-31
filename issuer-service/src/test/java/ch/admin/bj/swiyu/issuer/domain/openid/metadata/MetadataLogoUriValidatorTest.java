package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataLogoUriValidatorTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    @Test
    void nullUriShouldViolateNotNull() {
        MetadataImage m = new MetadataImage();
        m.setUri(null);
        Set<ConstraintViolation<MetadataImage>> violations = validator.validate(m);
        assertThat(violations).isNotEmpty();
    }

    @Test
    void invalidDataPrefixShouldViolate() {
        MetadataImage m = new MetadataImage();
        m.setUri("data:image/gif;base64,R0lGODdhAQABAIAAAAUEBA==");
        Set<ConstraintViolation<MetadataImage>> violations = validator.validate(m);
        assertThat(violations).isNotEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "data:image/png;base64,whatever",
            "data:image/jpeg;base64,whatever"})
    void invalidDataPrefixShouldViolate_thenSuccess(String logoUri) {
        MetadataImage m = new MetadataImage();
        m.setUri(logoUri);
        Set<ConstraintViolation<MetadataImage>> violations = validator.validate(m);
        assertThat(violations).isEmpty();
    }
}