/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.common.exception;

/**
 * Exception indicating that an error was made during a status list create call
 */
public class UpdateStatusListException extends RuntimeException {

    public UpdateStatusListException(String message) {
        super(message);
    }

    public UpdateStatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
