package ch.admin.bj.swiyu.issuer.pact.consumer;

import ch.admin.bit.jeap.security.resource.token.JeapAuthenticationContext;
import ch.admin.bit.jeap.security.test.jws.JwsBuilderFactory;
import lombok.experimental.UtilityClass;

import java.util.UUID;

@UtilityClass
public class PactConsumerSupport {

    /**
     * Builds a JWS (JSON Web Signature) token for authentication in tests.
     * Creates a valid token with fixed long period for the specified subject and system context.
     *
     * @param jwsBuilderFactory the factory used to create JWS token builders
     * @param subject the subject identifier for whom the token is issued
     * @param businessPartnerId the business partner identifier associated with the token,
     *                          used to assign business partner specific roles
     * @param roles the roles to be assigned to the user in the token
     * @return a serialized JWS token string that can be used in authorization headers
     * @throws IllegalArgumentException if jwsBuilderFactory, subject, or businessPartnerId is null
     */
    public static String buildJwsToken(final JwsBuilderFactory jwsBuilderFactory, final String subject, final UUID businessPartnerId, final String... roles) {
        return jwsBuilderFactory
                .createValidForFixedLongPeriodBuilder(subject, JeapAuthenticationContext.SYS)
                .withBusinessPartnerRoles(businessPartnerId.toString(), roles)
                .build()
                .serialize();
    }

}

