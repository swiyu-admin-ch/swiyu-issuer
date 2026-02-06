package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.actuate.health.Health;

/**
 * Abstract health checker that validates the signing capability of a configured verification method.
 * Consolidates duplicated logic between concrete implementations.
 * @param <T> concrete SignatureConfiguration type
 */
public abstract class AbstractSigningKeyVerificationHealthChecker<T extends SignatureConfiguration> extends CachedHealthChecker {

    private static final String HEALTH_DETAIL_FAILED_DIDS = "failedDids";
    private static final String HEALTH_DETAIL_SIGNING_KEY = "signingKeyVerificationMethod";
    private static final String HEALTH_DETAIL_SIGNING_ERROR = "error";
    private static final String TEST_JWT_SUBJECT = "health-check-test";

    private final KeyResolver keyResolver;
    private final JwsSignatureFacade jwsSignatureFacade;
    private final T properties;

    protected AbstractSigningKeyVerificationHealthChecker(KeyResolver keyResolver,
                                                          JwsSignatureFacade jwsSignatureFacade,
                                                          T properties) {
        this.keyResolver = keyResolver;
        this.jwsSignatureFacade = jwsSignatureFacade;
        this.properties = properties;
    }

    @Override
    protected void performCheck(Health.Builder builder) {
        String verificationMethod = properties.getVerificationMethod();

        JWK jwk = resolveDid(verificationMethod);
        if (jwk == null) {
            builder.down().withDetail(HEALTH_DETAIL_FAILED_DIDS, verificationMethod);
            return;
        }

        try {
            if (verifySigningCapability(jwk)) {
                builder.up().withDetail(HEALTH_DETAIL_SIGNING_KEY, verificationMethod);
            } else {
                builder.down().withDetail(HEALTH_DETAIL_SIGNING_KEY,
                    "Verification failed for " + verificationMethod);
            }
        } catch (Exception e) {
            builder.down()
                .withDetail(HEALTH_DETAIL_SIGNING_ERROR, e.getMessage())
                .withDetail(HEALTH_DETAIL_SIGNING_KEY, verificationMethod);
        }
    }

    private boolean verifySigningCapability(JWK jwk) throws KeyStrategyException, JOSEException {
        var signer = jwsSignatureFacade.createSigner(properties, null, null);

        SignedJWT testJwt = createTestJwt();
        testJwt.sign(signer);
        return verifySignature(testJwt, jwk);
    }

    private SignedJWT createTestJwt() {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).build();
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
            .subject(TEST_JWT_SUBJECT)
            .build();
        return new SignedJWT(header, payload);
    }

    private boolean verifySignature(SignedJWT signedJwt, JWK jwk) throws JOSEException{
        JWK publicKey = jwk.toECKey();

        JWSVerifier verifier = new ECDSAVerifier(publicKey.toECKey());
        return signedJwt.verify(verifier);
    }

    private JWK resolveDid(String verificationMethod) {
        if (verificationMethod == null || verificationMethod.isBlank()) {
            return null;
        }
        try {
            return keyResolver.resolveKey(verificationMethod);
        } catch (Exception e) {
            return null;
        }
    }
}

