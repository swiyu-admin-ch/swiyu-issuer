package ch.admin.bit.eid.issuer_management.config;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.text.ParseException;

@Configuration
@Validated
@Data
@ConfigurationProperties(prefix = "application")
public class ApplicationConfig {

    @NotNull
    private String externalUrl;

    @NotNull
    private Long offerValidity;

    /**
     * If set to true the service expects all
     * writing message bodies to be encoded as JWT
     */
    @NotNull
    private boolean enableJwtAuthentication;

    /**
     * If enableJWTAuthentication is set,
     * the JWTs will be checked against the public keys
     * stored in this json web key set.
     * Is expected to be a map with the key "keys"
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">Example how the JWKS is expected</a>
     */
    private String authenticationJwks;

    public JWKSet getAllowedKeySet() throws ParseException {
        return JWKSet.parse(authenticationJwks);
    }
}
