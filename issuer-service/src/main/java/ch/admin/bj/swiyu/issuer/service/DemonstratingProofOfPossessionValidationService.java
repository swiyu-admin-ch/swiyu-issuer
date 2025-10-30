package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Provide functions related to parsing and validating Demonstrating Proof of Possession (DPoP) JWTS
 * See <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
 */
@Service
@RequiredArgsConstructor
public class DemonstratingProofOfPossessionValidationService {

    public static final String DPOP_JWT_HEADER_TYP = "dpop+jwt";
    private final ApplicationProperties applicationProperties;

    /**
     * @return List of supported JWS (Json Web Signature) / JWT (Json Web Token) signing algorithms
     */
    public static List<String> getSupportedAlgorithms() {
        return List.of(JWSAlgorithm.ES256.getName());
    }

    /**
     * @param input String to be hashed
     * @return base64url-encoded SHA-256 hash of the ASCII encoding of the input
     */
    private static String sha256(@NotBlank String input) {
        try {
            // Get an instance of MessageDigest for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Convert the input string to bytes
            byte[] inputBytes = input.getBytes(StandardCharsets.US_ASCII);

            // Update the digest with the input bytes
            byte[] hashBytes = digest.digest(inputBytes);

            // Encode the hash bytes to a Base64 string
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Computs the SHA256 hash of the expected access token and compares it with the access token hash of the DPoP.
     *
     * @param expectedAccessToken the access token as received in the bearer token
     * @param dpopAccessTokenHash access token in sha256 hashed form as found in DPoP claim "ath"
     */
    private static void validateAccessTokenHash(String expectedAccessToken, String dpopAccessTokenHash) {
        if (!sha256(expectedAccessToken).equals(dpopAccessTokenHash)) {
            throw new DemonstratingProofOfPossessionException("Access token mismatch. ath must be base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private static void validateBoundPublicKey(SignedJWT dpopJwt, Map<String, Object> boundPublicKey) throws ParseException {
        var boundPublicKeyJWK = JWK.parse(boundPublicKey);
        if (!dpopJwt.getHeader().getJWK().equals(boundPublicKeyJWK)) {
            throw new DemonstratingProofOfPossessionException("Key mismatch", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
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
            validateAccessTokenHash(accessToken, dpopJwt.getJWTClaimsSet().getStringClaim("ath"));
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
            containsAllMandatoryDpopClaims(header, jwtClaims);
            // 4 - The typ JOSE Header Parameter has the value dpop+jwt.
            hasDpopType(header);
            // 5 - The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS],
            // is not none, is supported by the application, and is acceptable per local policy.
            matchesSupportedAlgorithms(header);
            // 6 - The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter.
            var key = header.getJWK();
            hasValidSignature(dpopJwt, key);
            // 7 - The jwk JOSE Header Parameter does not contain a private key.
            if (key.isPrivate()) {
                throw new DemonstratingProofOfPossessionException("Key provided in DPoP MUST NOT be private!", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
            }

            // 8 - The htm claim matches the HTTP method of the current request
            hasMatchingHttpMethod(request, jwtClaims);
            // 9 - The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.
            hasMatchingHttpUri(request, jwtClaims);

            // 10 - If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value.
            // Note: We always expect a nonce to be contained in every case
            // 11 - The creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window (see Section 11.1).
            // Note: While we achieve this by the fact that our self-contained nonces already contain this time window
            hasValidCreationTime(jwtClaims);
            hasValidSelfContainedNonce(jwtClaims);
            // Step 12 is not done in every case

            return dpopJwt;
        } catch (ParseException | JOSEException | URISyntaxException | NullPointerException e) {
            throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        }
    }

    private void hasValidCreationTime(JWTClaimsSet jwtClaims) {
        int acceptableProofTimeWindowSeconds = applicationProperties.getAcceptableProofTimeWindowSeconds();
        var upperBound = Instant.now().plusSeconds(acceptableProofTimeWindowSeconds);
        var lowerBound = Instant.now().minusSeconds(acceptableProofTimeWindowSeconds);
        var dpopIssuedAt = jwtClaims.getIssueTime().toInstant();
        if (dpopIssuedAt.isBefore(lowerBound) || dpopIssuedAt.isAfter(upperBound)) {
            throw new DemonstratingProofOfPossessionException("Issue time is not in an acceptable window; +/-%s".formatted(acceptableProofTimeWindowSeconds), DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void containsAllMandatoryDpopClaims(JWSHeader header, JWTClaimsSet jwtClaims) {
        var mandatoryDpopHeaderClaims = List.of("typ", "alg", "jwk");
        if (!header.toJSONObject().keySet().containsAll(mandatoryDpopHeaderClaims)) {
            throw new DemonstratingProofOfPossessionException("Missing mandatory JWS header claims", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        // Note: ath will be not always be relevant
        var mandatoryDpopPayloadClaims = List.of("jti", "htm", "htu", "iat", "nonce");
        if (!jwtClaims.getClaims().keySet().containsAll(mandatoryDpopPayloadClaims)) {
            throw new DemonstratingProofOfPossessionException("Missing mandatory JWT payload claims", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void hasMatchingHttpMethod(HttpRequest request, JWTClaimsSet jwtClaims) throws ParseException {
        if (!StringUtils.equalsIgnoreCase(request.getMethod().name(), jwtClaims.getStringClaim("htm"))) {
            throw new DemonstratingProofOfPossessionException("HTTP method mismatch between DPoP and request", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void hasValidSignature(SignedJWT dpopJwt, JWK key) throws JOSEException {
        if (!dpopJwt.verify(new ECDSAVerifier(key.toECKey()))) {
            throw new DemonstratingProofOfPossessionException("DPoP signature is invalid", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void hasDpopType(JWSHeader header) {
        if (!DPOP_JWT_HEADER_TYP.equals(header.getType().toString())) {
            throw new DemonstratingProofOfPossessionException("DPoP typ MUST be %s".formatted(DPOP_JWT_HEADER_TYP), DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void matchesSupportedAlgorithms(JWSHeader header) {
        var supportedAlgorithms = getSupportedAlgorithms();
        if (!supportedAlgorithms.contains(header.getAlgorithm().getName())) {
            throw new DemonstratingProofOfPossessionException("DPoP alg MUST be one of %s".formatted(
                    String.join(",", supportedAlgorithms)),
                    DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    /**
     * Check if the nonce is valid - not yet used and still within the acceptable time window
     */
    private void hasValidSelfContainedNonce(JWTClaimsSet jwtClaims) throws ParseException {
        var nonce = new SelfContainedNonce(jwtClaims.getStringClaim("nonce"));
        if (!nonce.isSelfContainedNonce() || !nonce.isValid(applicationProperties.getNonceLifetimeSeconds())) {
            throw new DemonstratingProofOfPossessionException("Must use valid server provided nonce", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private void hasMatchingHttpUri(HttpRequest request, JWTClaimsSet jwtClaims) throws URISyntaxException, ParseException {
        if (isInvalidUrl(request.getURI(), jwtClaims.getStringClaim("htu"))) {
            throw new DemonstratingProofOfPossessionException("URL mismatch between DPoP and request", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
    }

    private boolean isInvalidUrl(URI requestUri, String htu) throws URISyntaxException {
        // Create new URI without Query & Fragment, taking in account the external URI
        var externalUri = new URI(applicationProperties.getExternalUrl());
        var baseUri = new URI(requestUri.getScheme(),
                requestUri.getUserInfo(),
                externalUri.getHost(),
                externalUri.getPort(),
                requestUri.getPath(),
                null, null).normalize();
        var htuUri = new URI(htu).normalize();
        return !baseUri.equals(htuUri);
    }


}
