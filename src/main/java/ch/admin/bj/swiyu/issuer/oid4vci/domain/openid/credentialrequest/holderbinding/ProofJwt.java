/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

public class ProofJwt extends Proof {

    private final String jwt;
    private final int acceptableProofTimeWindowSeconds;
    private String holderKeyJson;

    public ProofJwt(ProofType proofType, String jwt) {
        this(proofType, jwt, 10);
    }

    public ProofJwt(ProofType proofType, String jwt, int acceptableProofTimeWindowSeconds) {
        super(proofType);
        this.jwt = jwt;
        this.acceptableProofTimeWindowSeconds = acceptableProofTimeWindowSeconds;
    }

    /**
     * Validates the Proof JWT according to <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-7.2.1.1">OID4VCI 7.2.1.1</a>
     */
    @Override
    public boolean isValidHolderBinding(String issuerId,
                                        List<String> supportedSigningAlgorithms,
                                        UUID nonce,
                                        Long tokenExpirationTimestamp) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(this.jwt);

            // check JOSE headers
            JWSHeader header = signedJWT.getHeader();

            // check if typ header is present and equals "openid4vci-proof+jwt"
            if (!header.getType().toString().equals(ProofType.JWT.getClaimTyp())) {
                throw proofException(String.format("Proof Type is not supported. Must be 'openid4vci-proof+jwt' but was %s", header.getType()));
            }

            // check if alg header is present and is supported
            if (header.getAlgorithm() == null || !supportedSigningAlgorithms.contains(header.getAlgorithm().getName())) {
                throw proofException("Proof Signing Algorithm is not supported");
            }

            // Check jwt body values:
            var claimSet = signedJWT.getJWTClaimsSet();

            // aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer Identifier.
            if (claimSet.getAudience().isEmpty() || !claimSet.getAudience().contains(issuerId)) {
                throw proofException("Audience claim is missing or incorrect");
            }

            // iat: REQUIRED (integer or floating-point number). The value of this claim MUST be the time at which the key proof was issued
            // 12.5 Proof Replay protection with issued at
            if (claimSet.getIssueTime() == null) {
                throw proofException("Issue Time claim is missing");
            }
            var proofIssueTime = signedJWT.getJWTClaimsSet().getIssueTime().toInstant();
            var now = Instant.now();
            if (proofIssueTime.isBefore(now.minusSeconds(acceptableProofTimeWindowSeconds))
                    || proofIssueTime.isAfter(now.plusSeconds(acceptableProofTimeWindowSeconds))) {
                throw proofException(String.format("Holder Binding proof was not issued at an acceptable time. Expected %d +/- %d seconds", now.getEpochSecond(), acceptableProofTimeWindowSeconds));
            }

            ECKey holderKey = getNormalizedECKey(header);
            JWSVerifier verifier = new ECDSAVerifier(holderKey);
            if (!signedJWT.verify(verifier)) {
                throw proofException("Proof JWT is not valid!");
            }

            // the nonce claim matches the server-provided c_nonce value, if the server had previously provided a c_nonce,
            var nonceString = nonce.toString();
            if (nonceString != null && !nonceString.equals(signedJWT.getJWTClaimsSet().getStringClaim("nonce"))) {
                throw proofException("Nonce claim does not match the server-provided c_nonce value");
            }

            if (tokenExpirationTimestamp != null && Instant.now().isAfter(Instant.ofEpochSecond(tokenExpirationTimestamp))) {
                throw proofException("Token is expired");
            }

            this.holderKeyJson = holderKey.toJSONString();

        } catch (ParseException e) {
            throw proofException("Provided Proof JWT is not parseable; " + e.getMessage());
        } catch (JOSEException e) {
            throw proofException("Key is not usable; " + e.getMessage());
        }

        return true;
    }

    @Override
    public String getBinding() {
        return this.holderKeyJson;
    }

    private static Oid4vcException proofException(String errorDescription) {
        return new Oid4vcException(CredentialRequestError.INVALID_PROOF, errorDescription);
    }

    /**
     * Gets the ECKey from either kid with did or the cnf entry
     *
     * @return the Holder's ECKey
     */
    private ECKey getNormalizedECKey(JWSHeader header) {
        var kid = header.getKeyID();

        // Public key present as did
        if (kid != null && kid.startsWith("did:")) {
            var didMatcher = Pattern.compile("did:[a-z]+(?=:.+)").matcher(kid);
            if (didMatcher.find() && !didMatcher.group().equals("did:jwk")) {
                throw proofException(String.format("Did method provided in kid attribute %s is not supported", didMatcher.group()));
            }
            if (didMatcher.group().equals("did:jwk")) {
                try {
                    return DidJwk.createFromDidJwk(kid).getJWK().toECKey();
                } catch (ParseException e) {
                    throw proofException(String.format("kid property %s could not be parsed to a JWK", kid));
                }
            }
        }

        // Public key is present as jwk
        if (header.getJWK() != null) {
            return header.getJWK().toECKey();
        }

        // No public key present which the current system supports
        throw proofException(String.format("None of the supported binding method/s was found in the header %s", header));
    }
}