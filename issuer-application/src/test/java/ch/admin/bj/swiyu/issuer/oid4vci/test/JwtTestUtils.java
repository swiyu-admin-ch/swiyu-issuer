package ch.admin.bj.swiyu.issuer.oid4vci.test;

import java.util.Base64;

public class JwtTestUtils {

    private static final int PAYLOAD_POSITION = 1;
    private static final String SPLIT_SIGNAL = "\\.";

    public static String getJWTPayload(String credential) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = credential.split(SPLIT_SIGNAL);
        return new String(decoder.decode(chunks[PAYLOAD_POSITION]));
    }
}
