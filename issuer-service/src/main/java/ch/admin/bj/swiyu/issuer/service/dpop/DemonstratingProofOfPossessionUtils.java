package ch.admin.bj.swiyu.issuer.service.dpop;

import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import com.nimbusds.jose.JWSAlgorithm;
import jakarta.validation.constraints.NotBlank;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for Demonstrating Proof of Possession (DPoP) related static methods.
 */
@UtilityClass
public class DemonstratingProofOfPossessionUtils {
    /**
     * @return List of supported JWS (Json Web Signature) / JWT (Json Web Token) signing algorithms
     */
    public List<String> getSupportedAlgorithms() {
        return List.of(JWSAlgorithm.ES256.getName());
    }

    /**
     * @param input String to be hashed
     * @return base64url-encoded SHA-256 hash of the ASCII encoding of the input
     */
    public String sha256(@NotBlank String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] inputBytes = input.getBytes(StandardCharsets.US_ASCII);
            byte[] hashBytes = digest.digest(inputBytes);
            return Base64.getUrlEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Computes the SHA256 hash of the expected access token and compares it with the access token hash of the DPoP.
     *
     * @param expectedAccessToken the access token as received in the bearer token
     * @param dpopAccessTokenHash access token in sha256 hashed form as found in DPoP claim "ath"
     */
    public void validateAccessTokenHash(String expectedAccessToken, String dpopAccessTokenHash) {
        if (!sha256(expectedAccessToken).equals(dpopAccessTokenHash)) {
            throw new DemonstratingProofOfPossessionException("Access token mismatch. ath must be base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }
}


