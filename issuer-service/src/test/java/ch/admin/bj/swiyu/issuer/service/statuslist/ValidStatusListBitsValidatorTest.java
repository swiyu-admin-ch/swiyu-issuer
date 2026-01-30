/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.dto.statuslist.ValidStatusListBitsValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class ValidStatusListBitsValidatorTest {

    private ValidStatusListBitsValidator bitsValidator;
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        bitsValidator = new ValidStatusListBitsValidator();
        context = mock(ConstraintValidatorContext.class);
    }

    @Test
    void testIsValid_withValidBits() {
        assertTrue(bitsValidator.isValid(1, context));
        assertTrue(bitsValidator.isValid(2, context));
        assertTrue(bitsValidator.isValid(4, context));
        assertTrue(bitsValidator.isValid(8, context));
    }

    @Test
    void testIsValid_withInvalidBits() {
        assertFalse(bitsValidator.isValid(null, context));
        assertFalse(bitsValidator.isValid(0, context));
        assertFalse(bitsValidator.isValid(3, context));
        assertFalse(bitsValidator.isValid(5, context));
        assertFalse(bitsValidator.isValid(7, context));
        assertFalse(bitsValidator.isValid(10, context));
    }
}