/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.test;

import java.util.Base64;

public class JwtTestUtils {

    private final static int HEADER_POSITION = 0;
    private final static int PAYLOAD_POSITION = 1;
    private final static String SPLIT_SIGNAL = "\\.";

    public static String getJWTPayload(String credential) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = credential.split(SPLIT_SIGNAL);
        return new String(decoder.decode(chunks[PAYLOAD_POSITION]));
    }
}
