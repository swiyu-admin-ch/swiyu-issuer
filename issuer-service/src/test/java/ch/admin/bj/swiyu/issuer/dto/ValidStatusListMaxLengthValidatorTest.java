package ch.admin.bj.swiyu.issuer.dto;

import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.ValidStatusListMaxLengthValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.*;

class ValidStatusListMaxLengthValidatorTest {

    private StatusListProperties properties;
    private ValidStatusListMaxLengthValidator validator;

    @BeforeEach
    void setup() {
        this.properties = mock(StatusListProperties.class);
        this.validator = new ValidStatusListMaxLengthValidator(properties);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 100, 1_000})
    void isValid_validLength_valid(int maxLength) {
        // Given
        var statusListCreate = new StatusListCreateDto();
        statusListCreate.setType("some type");
        statusListCreate.setMaxLength(maxLength);

        var config = new StatusListConfigDto();
        config.setBits(2);
        statusListCreate.setConfig(config);

        var context = mock(ConstraintValidatorContext.class);

        // When
        when(properties.getStatusListSizeLimit()).thenReturn(10_000);
        var isValid = this.validator.isValid(statusListCreate, context);

        // Then
        assertTrue(isValid);
    }

    @ParameterizedTest
    @ValueSource(ints = {10_000, 501, 2_000_000_000})
    void isValid_maxLengthTooHigh_invalid(int maxLength) {
        var context = mock(ConstraintValidatorContext.class);
        var contextBuilder = mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        when(context.buildConstraintViolationWithTemplate(messageCaptor.capture())).thenReturn(contextBuilder);

        // Given
        var statusListCreate = new StatusListCreateDto();
        statusListCreate.setType("some type");
        statusListCreate.setMaxLength(maxLength);

        var config = new StatusListConfigDto();
        config.setBits(2);
        statusListCreate.setConfig(config);

        // When
        when(properties.getStatusListSizeLimit()).thenReturn(1000);
        var isValid = this.validator.isValid(statusListCreate, context);

        // Then
        assertFalse(isValid);
        var message = messageCaptor.getValue();
        assertTrue(message.contains("cannot exceed the maximum size"));
    }

    @Test
    void isValid_missingConfig_invalid() {
        // Given
        var context = mock(ConstraintValidatorContext.class);
        var contextBuilder = mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        when(context.buildConstraintViolationWithTemplate(messageCaptor.capture())).thenReturn(contextBuilder);

        var statusListCreate = new StatusListCreateDto();
        statusListCreate.setType("some type");
        statusListCreate.setMaxLength(10);

        // When
        when(properties.getStatusListSizeLimit()).thenReturn(1000);
        var isValid = this.validator.isValid(statusListCreate, context);

        // Then
        assertFalse(isValid);
        var message = messageCaptor.getValue();
        assertTrue(message.contains("missing infos"));
    }

    @Test
    void isValid_noBitsInConfig_invalid() {
        var context = mock(ConstraintValidatorContext.class);
        var contextBuilder = mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        when(context.buildConstraintViolationWithTemplate(messageCaptor.capture())).thenReturn(contextBuilder);

        // Given
        var statusListCreate = new StatusListCreateDto();
        statusListCreate.setType("some type");
        statusListCreate.setMaxLength(10);
        statusListCreate.setConfig(new StatusListConfigDto());

        // When
        when(properties.getStatusListSizeLimit()).thenReturn(1000);
        var isValid = this.validator.isValid(statusListCreate, context);

        // Then
        assertFalse(isValid);
        var message = messageCaptor.getValue();
        assertTrue(message.contains("missing infos"));
    }
}
