/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import lombok.Getter;

@Getter
public enum StatusListType {
    TOKEN_STATUS_LIST("SwissTokenStatusList-1.0");

    final String displayName;

    StatusListType(String name) {
        this.displayName = name;
    }
}
