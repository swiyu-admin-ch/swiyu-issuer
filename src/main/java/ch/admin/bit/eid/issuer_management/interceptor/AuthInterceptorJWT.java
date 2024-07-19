package ch.admin.bit.eid.issuer_management.interceptor;

import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingRequestWrapper;

@AllArgsConstructor
@Slf4j
public class AuthInterceptorJWT implements HandlerInterceptor {
    private final JWKSet whitelistedKeys;

    private JWSVerifier buildVerifier(KeyType kty, JWK key) throws JOSEException {
        if (KeyType.EC.equals(kty)) {
            return new ECDSAVerifier(key.toECKey().toPublicJWK());
        } else if (KeyType.RSA.equals(kty)) {
            return new RSASSAVerifier(key.toRSAKey().toPublicJWK());
        }
        throw new JOSEException("Unsupported Key Type %s".formatted(kty));
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Read can not be checked with JWT body
        if ("GET".equalsIgnoreCase(request.getMethod())) {
            return HandlerInterceptor.super.preHandle(request, response, handler);
        }
        try {
            JWTResolveRequestWrapper wrappedRequest = new JWTResolveRequestWrapper(
                    new ContentCachingRequestWrapper(request));
            SignedJWT jwt = wrappedRequest.getJwt();
            JWSHeader jwtHeader = jwt.getHeader();
            JWK matchingKey = whitelistedKeys.getKeyByKeyId(jwtHeader.getKeyID());
            KeyType kty = matchingKey.getKeyType();
            if (!jwt.verify(buildVerifier(kty, matchingKey))){
                log.warn("Request with invalid JWT encoding intercepted");
                throw new BadRequestException("Request JWT verification failed");
            }

            return HandlerInterceptor.super.preHandle(wrappedRequest, response, handler);
        } catch (Exception e) {
            log.info("Parsing communication JWT failed.", e);
            throw new BadRequestException("Request is not JWT encoded");
        }
    }
}
