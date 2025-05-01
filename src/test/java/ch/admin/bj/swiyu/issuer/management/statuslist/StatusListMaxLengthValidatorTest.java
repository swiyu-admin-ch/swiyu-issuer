/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.statuslist;

import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.ValidStatusListMaxLengthValidator;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StatusListMaxLengthValidatorTest {

    private final StatusListCreateDto dto = new StatusListCreateDto();
    private ValidStatusListMaxLengthValidator validator;

    @MockitoBean
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        StatusListProperties statusListProperties = new StatusListProperties();
        statusListProperties.setStatusListSizeLimit(1000);
        validator = new ValidStatusListMaxLengthValidator(statusListProperties);
        context = mock(ConstraintValidatorContext.class);
        when(context.buildConstraintViolationWithTemplate(any())).thenReturn(mock(ConstraintValidatorContext.ConstraintViolationBuilder.class));
        dto.setType(StatusListTypeDto.TOKEN_STATUS_LIST);
        setConfigBits(8);
    }

    @Test
    void testIsValid_withValidMaxLength() {
        dto.setMaxLength(100);

        assertTrue(validator.isValid(dto, context));
    }

    @Test
    void testIsValid_withValidMaxLength1000() {
        dto.setMaxLength(1000);
        setConfigBits(1);

        assertTrue(validator.isValid(dto, context));
    }


    @Test
    void testIsValid_withInvalidMaxLength() {
        dto.setMaxLength(200);

        assertFalse(validator.isValid(dto, context));
    }

    @Test
    void testIsValid_withExceedingMaxLength() {
        dto.setMaxLength(150);
        setConfigBits(10);

        assertFalse(validator.isValid(dto, context));
    }

    private void setConfigBits(int value) {

        StatusListConfigDto configDto = new StatusListConfigDto();
        configDto.setBits(value);
        dto.setConfig(configDto);
    }
}