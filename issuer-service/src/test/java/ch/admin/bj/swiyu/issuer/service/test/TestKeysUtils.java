package ch.admin.bj.swiyu.issuer.service.test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.JWKGenerator;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.stream.IntStream;

/**
 * Small factory methods for P-256 test keys.
 * <p>
 * Key generation can only fail on a broken JCA setup, so the checked {@link JOSEException} is rethrown
 * as {@link IllegalStateException}. Callers therefore need neither {@code throws} nor {@code assertDoesNotThrow}.
 */
@UtilityClass
public class TestKeysUtils {

    /**
     * @return a P-256 key for signatures with the given key id
     */
    public static ECKey signingKey(String keyId) {
        return generate(new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID(keyId));
    }

    /**
     * @return {@code count} P-256 signing keys with the key ids {@code keyIdPrefix + 0}, {@code keyIdPrefix + 1}, ...
     */
    public static List<ECKey> signingKeys(String keyIdPrefix, int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> signingKey(keyIdPrefix + i))
                .toList();
    }

    /**
     * @return a P-256 key for encryption using {@link JWEAlgorithm#ECDH_ES} with the given key id
     */
    public static ECKey encryptionKey(String keyId) {
        return encryptionKey(keyId, JWEAlgorithm.ECDH_ES);
    }

    /**
     * @return a P-256 key for encryption using the given algorithm and key id
     */
    public static ECKey encryptionKey(String keyId, JWEAlgorithm algorithm) {
        return generate(new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).algorithm(algorithm).keyID(keyId));
    }

    private static ECKey generate(JWKGenerator<ECKey> generator) {
        try {
            return generator.generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not generate test key", e);
        }
    }
}
