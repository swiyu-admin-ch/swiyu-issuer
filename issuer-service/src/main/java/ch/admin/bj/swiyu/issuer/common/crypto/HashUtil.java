package ch.admin.bj.swiyu.issuer.common.crypto;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class HashUtil {

    /**
     * This method creates a HMAC (Hash-based Message Authentication Code) using the provided message.
     * 
     * @param message         The input message to be HMAC'd.
     * @param key             The key used in HMAC for hashing.
     * @return                A Base64 encoded string representation of the resulting HMAC.
     * @throws IllegalArgumentException If the message or the key is null
     */
    public static String createHMAC(String message, KeyParameter key) {
        // We use bouncy castle as it is more performant than JCE
        HMac hmac = new HMac(SHA256Digest.newInstance());
        hmac.init(key);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        hmac.update(messageBytes, 0, messageBytes.length);
        byte[] hmacOut = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacOut, 0);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hmacOut);
    }

    /**
     * Compares the digests of two strings in a time 
     * constant manner preventing timing attack
     * @param digestA
     * @param digestB
     * @return true if both are equal
     */
    public static boolean equalsConstantTime(String digestA, String digestB) {
        return MessageDigest.isEqual(digestA.getBytes(StandardCharsets.UTF_8), digestB.getBytes(StandardCharsets.UTF_8));
    }
}
