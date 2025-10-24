package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionError;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * A service collecting functions related to Demonstrating Proof of Possession (DPoP)
 * See <a href="https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid">RFC9449</a>
 * More summarized for users in
 * <a href="https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html">spring-security documentation</a>
 */
@Service
@RequiredArgsConstructor
public class DemonstratingProofOfPossessionService {

    private final ApplicationProperties applicationProperties;
    private final UrlRewriteProperties rewriteProperties;
    private final NonceService nonceService;
    private final CredentialOfferRepository credentialOfferRepository;

    private static List<String> getSupportedAlgorithms() {
        return List.of("ES256");
    }

    private static void containsAllMandatoryDpopClaims(JWSHeader header, JWTClaimsSet jwtClaims) {
        var mandatoryDpopHeaderClaims = List.of("typ", "alg", "jwk");
        // Note: ath will be not always be relevant
        var mandatoryDpopPayloadClaims = List.of("jti", "htm", "htu", "iat", "nonce");
        if (!header.toJSONObject().keySet().containsAll(mandatoryDpopHeaderClaims)) {
            throw new DemonstratingProofOfPossessionException("Missing mandatory JWS header claims", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        if (!jwtClaims.getClaims().keySet().containsAll(mandatoryDpopPayloadClaims)) {
            throw new DemonstratingProofOfPossessionException("Missing mandatory JWT payload claims", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
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

    public void addDpopNonce(HttpHeaders headers) {
        headers.set("DPoP-Nonce", nonceService.createNonce().nonce());
    }

    @Transactional
    public void registerDpop(@NotBlank String preAuthCode, @Nullable String dpop, HttpRequest request) {
        if (isDopUnused(dpop)) {
            return;
        }
        try {
            var dpopJwt = parseDpopJwt(dpop, request);
            var credentialOffer = credentialOfferRepository.findByPreAuthorizedCode(UUID.fromString(preAuthCode)).orElseThrow();
            credentialOffer.setDPoPKey(dpopJwt.getHeader().getJWK().toJSONObject());
            credentialOfferRepository.save(credentialOffer);
        } catch (ParseException | JOSEException | URISyntaxException | NullPointerException e) {
            throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        }
    }

    @Transactional
    public void validateDpop(@NotBlank String accessToken, @Nullable String dpop, @NotNull HttpRequest request) {
        if (isDopUnused(dpop)) {
            return;
        }
        try {
            var dpopJwt = parseDpopJwt(dpop, request);
            var credentialOffer = credentialOfferRepository.findByAccessToken(UUID.fromString(accessToken)).orElseThrow();
            // https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
            // 12 - If presented to a protected resource in conjunction with an access token,
            // * ensure that the value of the ath claim equals the hash of that access token, and
            if (!dpopJwt.getJWTClaimsSet().getStringClaim("ath").equals(sha256(accessToken))) {
                throw new DemonstratingProofOfPossessionException("Access token mismatch. ath must be base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
            }
            // * confirm that the public key to which the access token is bound matches the public key from the DPoP proof.
            if (!dpopJwt.getHeader().getJWK().equals(JWK.parse(credentialOffer.getDpopKey()))) {
                throw new DemonstratingProofOfPossessionException("Key mismatch", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
            }

        } catch (ParseException | JOSEException | URISyntaxException | NullPointerException e) {
            throw new DemonstratingProofOfPossessionException("Malformed DPoP", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF, e);
        }
    }

    public OpenIdConfigurationDto addSigningAlgorithmsSupported(OpenIdConfigurationDto openIdConfiguration) {
        var builder = openIdConfiguration.toBuilder();
        builder.dpop_signing_alg_values_supported(getSupportedAlgorithms());
        return builder.build();
    }

    /**
     * Parses jwt and validates that it is a dpop according to RFC9449
     *
     * @return the parsed jwt
     * @throws ParseException if dpop jwt is malformed
     * @throws JOSEException  if the key is malformed or mismatching the algorithm
     */
    private SignedJWT parseDpopJwt(String dpop, HttpRequest request) throws ParseException, JOSEException, URISyntaxException {
        // See https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
        // 2 - The DPoP HTTP request header field value is a single and well-formed JWT.
        var dpopJwt = SignedJWT.parse(dpop);
        // 3 - All required claims per Section 4.2 are contained in the JWT.
        var header = dpopJwt.getHeader();
        var jwtClaims = dpopJwt.getJWTClaimsSet();
        containsAllMandatoryDpopClaims(header, jwtClaims);
        // 4 - The typ JOSE Header Parameter has the value dpop+jwt.
        if (!header.getType().toString().equals("dpop+jwt")) {
            throw new DemonstratingProofOfPossessionException("DPoP typ MUST be dpop+jwt", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        // 5 - The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS],
        // is not none, is supported by the application, and is acceptable per local policy.
        var supportedAlgorithms = getSupportedAlgorithms();
        if (!supportedAlgorithms.contains(header.getAlgorithm().getName())) {
            throw new DemonstratingProofOfPossessionException("DPoP alg MUST be one of %s".formatted(
                    String.join(",", supportedAlgorithms)),
                    DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        // 6 - The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter.
        var key = header.getJWK();
        if (!dpopJwt.verify(new ECDSAVerifier(key.toECKey()))) {
            throw new DemonstratingProofOfPossessionException("DPoP signature is invalid", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        // 7 - The jwk JOSE Header Parameter does not contain a private key.
        if (key.isPrivate()) {
            throw new DemonstratingProofOfPossessionException("Key provided in DPoP MUST NOT be private!", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }

        // 8 - The htm claim matches the HTTP method of the current request

        if (!StringUtils.equalsIgnoreCase(request.getMethod().name(), jwtClaims.getStringClaim("htm"))) {
            throw new DemonstratingProofOfPossessionException("HTTP method mismatch between DPoP and request", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }
        // 9 - The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.


        if (isInvalidUrl(request.getURI(), jwtClaims.getStringClaim("htu"))) {
            throw new DemonstratingProofOfPossessionException("URL mismatch between DPoP and request", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }

        // 10 - If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value.
        // 11 - The creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window (see Section 11.1).
        var nonce = new SelfContainedNonce(jwtClaims.getStringClaim("nonce"));
        if (!nonce.isSelfContainedNonce() || !nonce.isValid(applicationProperties.getNonceLifetimeSeconds())) {
            throw new DemonstratingProofOfPossessionException("Must use valid server provided nonce", DemonstratingProofOfPossessionError.INVALID_DPOP_PROOF);
        }

        return dpopJwt;
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

    /**
     * Checks if the dpop is missing.
     *
     * @param dpop
     * @return
     */
    private boolean isDopUnused(String dpop) {
        if (StringUtils.isBlank(dpop)) {
            if (applicationProperties.isDpopEnforce()) {
                throw new DemonstratingProofOfPossessionException("Authorization server requires nonce in DPoP proof",
                        DemonstratingProofOfPossessionError.USE_DPOP_NONCE);
            } else {
                // Not enforced, so not having a dpop is fine
                return true;
            }
        }
        return false;
    }
}
