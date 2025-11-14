package ch.admin.bj.swiyu.issuer.infrastructure.health;


import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import org.springframework.stereotype.Component;

/**
 * Health checker for Status List signing key verification using shared abstract base.
 */
@Component
public class StatusListSigningKeyVerificationHealthChecker extends AbstractSigningKeyVerificationHealthChecker<StatusListProperties> {

    public StatusListSigningKeyVerificationHealthChecker(KeyResolver keyResolver,
                                                         StatusListProperties statusListProperties,
                                                         SignatureService signatureService) {
        super(keyResolver, signatureService, statusListProperties);
    }
}
