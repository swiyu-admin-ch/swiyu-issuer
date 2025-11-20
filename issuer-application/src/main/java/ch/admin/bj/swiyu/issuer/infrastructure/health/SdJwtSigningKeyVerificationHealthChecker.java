package ch.admin.bj.swiyu.issuer.infrastructure.health;


import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import org.springframework.stereotype.Component;

/**
 * Health checker for SD-JWT signing key verification using shared abstract base.
 */
@Component
public class SdJwtSigningKeyVerificationHealthChecker extends AbstractSigningKeyVerificationHealthChecker<SdjwtProperties> {

    // Lombok won't generate a constructor calling super, define explicit one
    public SdJwtSigningKeyVerificationHealthChecker(KeyResolver keyResolver,
                                                    SdjwtProperties sdjwtProperties,
                                                    SignatureService signatureService) {
        super(keyResolver, signatureService, sdjwtProperties);
    }
}
