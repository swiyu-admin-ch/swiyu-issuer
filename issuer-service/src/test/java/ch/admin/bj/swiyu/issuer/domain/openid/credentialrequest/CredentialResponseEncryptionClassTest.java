package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CredentialResponseEncryptionClassTest {

    @Test
    void whenConstructingWitValidKey_thenSuccess() {
        var key = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("TestKey").algorithm(JWEAlgorithm.ECDH_ES).keyUse(KeyUse.ENCRYPTION).generate());
        var keyJson = key.toPublicJWK().toJSONObject();
        var credentialResponseEncryption = assertDoesNotThrow(() -> new CredentialResponseEncryptionClass(keyJson, EncryptionMethod.A256GCM.getName()));
        assertDoesNotThrow(credentialResponseEncryption::getAlg);
        assertDoesNotThrow(credentialResponseEncryption::getEnc);
    }

    @Test
    void whenMissingAlg_thenThrowsOid4vcException() {
        var key = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("TestKey").keyUse(KeyUse.ENCRYPTION).generate());
        var keyJson = key.toPublicJWK().toJSONObject();
        assertThrows(Oid4vcException.class, () -> new CredentialResponseEncryptionClass(keyJson, EncryptionMethod.A256GCM.getName()));
    }

}