/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.common.exception;

/**
 * Exception indicating that an error was made during a status list create call
 */
public class CreateStatusListException extends RuntimeException {

    public CreateStatusListException(String message) {
        super(message);
    }

    public CreateStatusListException(String message, Throwable cause) {
        super(message, cause);
    }
}
