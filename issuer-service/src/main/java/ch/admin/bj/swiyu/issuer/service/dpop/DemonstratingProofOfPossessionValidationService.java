package ch.admin.bj.swiyu.issuer.service.dpop;

import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.dpop.DpopHashUtil;
import ch.admin.bj.swiyu.dpop.DpopJwtValidator;
import ch.admin.bj.swiyu.dpop.DpopValidationException;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Clock;
import java.util.Map;

/**
 * Provide functions related to parsing and validating Demonstrating Proof of Possession (DPoP) JWTS
 * See <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
 */
@Service
@RequiredArgsConstructor
public class DemonstratingProofOfPossessionValidationService {

    private final ApplicationProperties applicationProperties;
    private final NonceService nonceService;

    /**
     * Validate if the dpopJwt (provided key) and boundPublicKey (expected key) are the same
     *
     * @param dpopJwt        parsed dpop jwt
     * @param boundPublicKey public key from initial registration or latest update of the bound dpop public key
     */
    public void validateBoundPublicKey(SignedJWT dpopJwt, Map<String, Object> boundPublicKey) {
        try {
            var boundPublicKeyJWK = JWK.parse(boundPublicKey);
            if (!dpopJwt.getHeader().getJWK().equals(boundPublicKeyJWK)) {
                throw new DemonstratingProofOfPossessionException("Key mismatch", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
            }
        } catch (ParseException e) {
            // The previously registered key can not be parsed anymore.
            // Something must have gone wrong in registration or the registered key got somehow corrupted.
            throw new IllegalStateException("Bound public key can not be parsed anymore", e);
        }
    }

    /**
     * Validates if the validated DPoP is associated with the access token and public key.
     *
     * @param accessToken    the access token the DPoP is bound to, as used for bearer token
     * @param dpopJwt        Parsed JWT of the DPoP
     * @param boundPublicKey The public key bound to the access token as Json Web Key (JWK)
     * @throws DemonstratingProofOfPossessionException if the DPoP is not correctly associated with the access token or the key.
     * @see DemonstratingProofOfPossessionValidationService#parseDpopJwt(String dpop, HttpRequest)
     */
    public void validateAccessTokenBinding(String accessToken, SignedJWT dpopJwt, Map<String, Object> boundPublicKey) {
        try {
            // https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
            // 12 - If presented to a protected resource in conjunction with an access token,
            // * ensure that the value of the ath claim equals the hash of that access token, and
            DpopHashUtil.validateAccessTokenHash(accessToken, dpopJwt.getJWTClaimsSet().getStringClaim("ath"));
            // * confirm that the public key to which the access token is bound matches the public key from the DPoP proof.
            validateBoundPublicKey(dpopJwt, boundPublicKey);
        } catch (ParseException e) {
            throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        }
    }

    /**
     * Parses jwt and validates that it is a DPoP according to RFC9449
     *
     * @param dpop    Demonstrating Proof of Possession JWT as serialized string
     * @param request HTTP Request the dpop was provided with
     * @return the parsed jwt
     * @throws DemonstratingProofOfPossessionException if the DPoP is invalid
     */
    public SignedJWT parseDpopJwt(String dpop, HttpRequest request) {
        try {
            // See https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
            // 2 - The DPoP HTTP request header field value is a single and well-formed JWT.
            var dpopJwt = SignedJWT.parse(dpop);
            // 3 - All required claims per Section 4.2 are contained in the JWT.
            var header = dpopJwt.getHeader();
            var jwtClaims = dpopJwt.getJWTClaimsSet();
            DpopJwtValidator.validateMandatoryClaims(header, jwtClaims);
            // 4 - The typ JOSE Header Parameter has the value dpop+jwt.
            DpopJwtValidator.validateTyp(header);
            // 5 - The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS],
            // is not none, is supported by the application, and is acceptable per local policy.
            DpopJwtValidator.validateAlgorithm(header, DpopConstants.SUPPORTED_ALGORITHMS);
            // 6 - The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter.
            var key = header.getJWK();
            DpopJwtValidator.validateSignature(dpopJwt, key);
            // 7 - The jwk JOSE Header Parameter does not contain a private key.
            DpopJwtValidator.validatePublicKeyNotPrivate(key);
            // 8 - The htm claim matches the HTTP method of the current request
            DpopJwtValidator.validateHtm(request.getMethod().name(), jwtClaims);
            // 9 - The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.
            DpopJwtValidator.validateHtu(request.getURI(), jwtClaims.getStringClaim("htu"),
                    new URI(applicationProperties.getExternalUrl()));
            // 10 - If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value.
            // Note: We always expect a nonce to be contained in every case
            // 11 - The creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window (see Section 11.1).
            // Note: While we achieve this by the fact that our self-contained nonces already contain this time window
            DpopJwtValidator.validateIssuedAt(jwtClaims, applicationProperties.getAcceptableProofTimeWindowSeconds(), Clock.systemUTC());
            hasValidSelfContainedNonce(jwtClaims);
            // Step 12 is not done in every case
            return dpopJwt;
        } catch (ParseException | JOSEException | URISyntaxException | NullPointerException e) {
            throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        } catch (DpopValidationException e) {
            throw new DemonstratingProofOfPossessionException(e.getMessage(), DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        }
    }

    /**
     * Check if the nonce is valid - not yet used and still within the acceptable time window
     */
    private void hasValidSelfContainedNonce(JWTClaimsSet jwtClaims) throws ParseException {
        if (!nonceService.isValidSelfContainedNonce(jwtClaims.getStringClaim("nonce"))) {
            throw new DemonstratingProofOfPossessionException("Must use valid server provided nonce", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

}
