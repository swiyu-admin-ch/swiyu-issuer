/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.NotImplementedError;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.stream.Collectors;


/**
 * Wrapper for a request with a JWT encoded content.
 * Reading from the wrapper only returns the claims of the JWT as the Request
 * body.
 * Create by using the static method <code>createAndValidate</code>
 */
@Getter
@Slf4j
public class JWTResolveRequestWrapper extends HttpServletRequestWrapper {
    private final SignedJWT jwt;
    private final String dataClaim;

    public JWTResolveRequestWrapper(HttpServletRequest request) throws IOException, ParseException {
        super(request);
        var mapper = new ObjectMapper();
        String jwtString = request.getReader().lines().collect(Collectors.joining());
        this.jwt = SignedJWT.parse(jwtString);
        // Todo check
        this.dataClaim = mapper.readTree(jwt.getJWTClaimsSet().getStringClaim("data")).toString();
    }

    private static JWSVerifier buildVerifier(KeyType kty, JWK key) throws JOSEException {
        if (KeyType.EC.equals(kty)) {
            return new ECDSAVerifier(key.toECKey().toPublicJWK());
        } else if (KeyType.RSA.equals(kty)) {
            return new RSASSAVerifier(key.toRSAKey().toPublicJWK());
        }
        throw new JOSEException("Unsupported Key Type %s".formatted(kty));
    }

    public static JWTResolveRequestWrapper createAndValidate(HttpServletRequest request, JWKSet allowedKeys) {
        try {
            JWTResolveRequestWrapper wrappedRequest = new JWTResolveRequestWrapper(request);
            SignedJWT jwt = wrappedRequest.getJwt();
            JWSHeader jwtHeader = jwt.getHeader();
            JWK matchingKey = allowedKeys.getKeyByKeyId(jwtHeader.getKeyID());
            if (matchingKey == null) {
                log.warn("No matching allowed key has been found for the received JWT");
                throw new BadRequestException("Unknown Key has been used in signing the JWT");
            }
            KeyType kty = matchingKey.getKeyType();
            if (!jwt.verify(buildVerifier(kty, matchingKey))) {
                log.warn("Request with invalid JWT encoding intercepted");
                throw new BadRequestException("Request JWT verification failed");
            }
            return wrappedRequest;
        } catch (Exception e) {
            log.info("Parsing communication JWT failed.", e);
            throw new BadRequestException("Request is not JWT encoded");
        }
    }

    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream buffer = new ByteArrayInputStream(dataClaim.getBytes());
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return buffer.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                throw new NotImplementedError("setReadListener Not implemented");
            }

            @Override
            public int read() {
                return buffer.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }
}
