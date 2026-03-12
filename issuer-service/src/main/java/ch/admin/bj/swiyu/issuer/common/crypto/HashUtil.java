package ch.admin.bj.swiyu.issuer.common.crypto;


import java.util.Base64;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

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
        byte[] messageBytes = message.getBytes();
        hmac.update(messageBytes, 0, messageBytes.length);
        byte[] hmacOut = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacOut, 0);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hmacOut);
    }
}
