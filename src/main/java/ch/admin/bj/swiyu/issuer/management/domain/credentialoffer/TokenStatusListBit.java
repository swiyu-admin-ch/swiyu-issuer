/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenStatusListBit {
    VALID(0),
    REVOKE(1),
    SUSPEND(2);

    /**
     * Value as defined in Token Status List Spec
     */
    private final int value;
}
