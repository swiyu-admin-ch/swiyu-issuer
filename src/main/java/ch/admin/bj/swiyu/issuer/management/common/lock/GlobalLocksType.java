/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.common.lock;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * A list of global locks in the application.
 */
@Getter
@RequiredArgsConstructor
public enum GlobalLocksType {
    STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH("STATUS_REGISTRY_TOKEN_MANAGER_TOKEN_REFRESH");

    private final String lockId;
}
