package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.jwtvalidator.DidJwtValidator;
import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public final class AttestationJwt {

    @Deprecated(since = "OID4VCI 1.0") // remove later
    private static final String KEY_ATTESTATION_TYPE_ID1 = "keyattestation+jwt";
    private static final Set<AttackPotentialResistance> SUPPORTED_ATTACK_POTENTIAL_RESISTANCE = Set.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC, AttackPotentialResistance.ISO_18045_HIGH);
    private static final Set<String> ALLOWED_TYPES = Set.of(KEY_ATTESTATION_TYPE_ID1, "key-attestation+jwt");

    // For now we only support ECDSA for Attestations
    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);
    private static final DidKidParser kidParser = new DidKidParser();
    private final SignedJWT signedJWT;
    private final List<AttackPotentialResistance> attestedAttackPotentialResistance;
    private final JWTClaimsSet claims;

    private AttestationJwt(SignedJWT signedJWT, List<AttackPotentialResistance> attestedAttackPotentialResistance) throws ParseException {
        this.signedJWT = signedJWT;
        this.attestedAttackPotentialResistance = attestedAttackPotentialResistance;
        this.claims = signedJWT.getJWTClaimsSet();
    }


    /**
     * Creates an Attestation JWT from a base64 encoded JWT, performing basic validation.
     *
     * @param jwt base64 encoded JWT
     * @param enforceSwissProfileVersioning if true, requires profile_version in the JWT header
     */
    public static AttestationJwt parseJwt(String jwt, boolean enforceSwissProfileVersioning) throws ParseException {
        var parsedJwt = SignedJWT.parse(jwt);
        var claims = parsedJwt.getJWTClaimsSet();
        // Check required Headers & Payload
        String issuerDid = validateHeader(parsedJwt.getHeader(), enforceSwissProfileVersioning);
        validateBody(claims, issuerDid);
        return new AttestationJwt(parsedJwt, extractSupportedAttackPotentialResistance(claims));
    }

    /**
     * @param jwtClaimsSet The JWT Body to be checked for Attestation JWT Required attributes
     * @throws IllegalArgumentException if one of the checks fails
     */
    private static void validateBody(JWTClaimsSet jwtClaimsSet, String expectedAttestationIssuerDid) {
        DefaultJWTClaimsVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(
                    null,                  // no required audience
                    new JWTClaimsSet.Builder().issuer(expectedAttestationIssuerDid).build(), // Issuer MUST match DID.
                    Set.of( // Fields Requried to be present according to Swiss Profile 1.0
                        JWTClaimNames.ISSUER, 
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "attested_keys",
                        "key_storage"
                    ),
                    Set.of()               // no prohibited claims – iss is ignored, not forbidden
            );
        try {
            verifier.verify(jwtClaimsSet, null);
            // iat should not be after now with clock skew considered
            var issuedAtTime = jwtClaimsSet.getIssueTime().toInstant();
            if (issuedAtTime.isAfter(Instant.now().plusSeconds(verifier.getMaxClockSkew()))) {
                throw new IllegalArgumentException("IssueTime is in the future");
            }
        } catch (BadJWTException e) {
            throw new IllegalArgumentException("Bad Attestation JWT - " + e.getMessage(), e);
        }
    }

    private static List<AttackPotentialResistance> extractSupportedAttackPotentialResistance(JWTClaimsSet jwtClaimsSet) {
        var supportedKeyStores = SUPPORTED_ATTACK_POTENTIAL_RESISTANCE
                .stream()
                .map(AttackPotentialResistance::getValue)
                .collect(Collectors.toSet());
        var keyStorage = jwtClaimsSet.getClaim("key_storage");
        if (!(keyStorage instanceof List)) {
            throw new IllegalArgumentException("list of attested key_storage is required");
        }
        // Intersection of provided and supported
        supportedKeyStores.retainAll(((List<?>) keyStorage)
                .stream()
                .map(Object::toString)
                .toList());
        if (supportedKeyStores.isEmpty()) {
            throw new IllegalArgumentException("No Supported key_storage found. Only Supporting " + String.join(", ", supportedKeyStores));
        }
        return supportedKeyStores.stream().map(AttackPotentialResistance::parse).toList();
    }

    /**
     * Validates the JWT header for required Swiss Profile parameters.
     *
     * @param header the JWT header
     * @param enforceSwissProfileVersioning whether to enforce Swiss Profile versioning
     */
    static String validateHeader(JWSHeader header, boolean enforceSwissProfileVersioning) {

        validateType(header);

        validateAlgorithm(header);

        if (enforceSwissProfileVersioning) {
            validateSwissProfileVersion(header);
        }
        return validateKid(header);
    }

    private static String validateKid(JWSHeader header) {
        var kid = header.getKeyID();
        if (kid == null) {
            throw new IllegalArgumentException("Key ID (kid) must be present");
        }
        try {
            return kidParser.getDidFromAbsoluteKid(kid);
        } catch (JwtValidatorException e) {
            throw new IllegalArgumentException(e);
        }
    }


    private static void validateType(JWSHeader header) {
        var type = header.getType();
        if (type == null || !ALLOWED_TYPES.contains(type.getType())) {
            throw new IllegalArgumentException("Typ must be one of " + String.join(", ", ALLOWED_TYPES));
        }
    }

    private static void validateAlgorithm(JWSHeader header) {
        var algorithm = header.getAlgorithm();
        if (algorithm == null || !ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Algorithm must be one of "
                    + ALLOWED_ALGORITHMS.stream().map(JWSAlgorithm::getName).collect(Collectors.joining(", ")));
        }
        if (StringUtils.isEmpty((header.getKeyID()))) {
            throw new IllegalArgumentException("KeyID MUST be set");
        }
    }

    private static void validateSwissProfileVersion(JWSHeader header) {
        var profileVersion = header.getCustomParam(SwissProfileVersions.PROFILE_VERSION_PARAM);
        if (profileVersion == null) {
            throw new IllegalArgumentException("Missing 'profile_version' in key attestation header");
        }
        if (!SwissProfileVersions.ISSUANCE_PROFILE_VERSION.equals(profileVersion.toString())) {
            throw new IllegalArgumentException("Invalid 'profile_version' in key attestation header");
        }
    }

    /**
     * @param trustedAttestationProviders list of trusted issuers
     * @throws IllegalArgumentException if the issuer of the jwt is not matching the list of trusted attestation providers
     */
    public void throwIfNotTrustedAttestationProvider(@NotNull List<String> trustedAttestationProviders) throws IllegalArgumentException {
        String attestationKeyId = signedJWT.getHeader().getKeyID();
        String attestationProviderDid = kidParser.getDidFromAbsoluteKid(attestationKeyId);
        if (!trustedAttestationProviders.contains(attestationProviderDid)) {
            throw new IllegalArgumentException("The JWT issuer %s is not in the list of trusted attestation providers %s.".formatted(claims.getIssuer(), String.join(", ", trustedAttestationProviders)));
        }
    }

    /**
     * @param keyResolver service to resolve the public JWK with
     * @param resistance  Which resistance must be attested
     * @return true if the attestation is valid and the resistance is matching
     * @throws JOSEException if the fetched Key can not be parsed as a supported JWSVerifier
     */
    public boolean isValidAttestation(@NotNull KeyResolver keyResolver, @NotNull List<AttackPotentialResistance> resistance, DidJwtValidator validator) throws JOSEException {
        var header = signedJWT.getHeader();
        var key = keyResolver.resolveKey(header.getKeyID());
        try {
            validator.validateJwt(signedJWT.getParsedString(), key);
        } catch (JwtValidatorException e) {
            throw new JOSEException("JWT verification failed", e);
        }
        if (resistance.isEmpty()) {
            return true;
        }
        var providedResistanceSet = new HashSet<>(attestedAttackPotentialResistance);
        providedResistanceSet.retainAll(resistance);
        // We only care IF we have a matching resistance spec
        return !providedResistanceSet.isEmpty();
    }

    /**
     * Checks whether the given proof key is contained in the {@code attested_keys} claim of this attestation.
     * Comparison is performed using JWK thumbprints as defined in
     * <a href="https://www.rfc-editor.org/rfc/rfc7638">RFC 7638</a> to ensure canonical key comparison
     * independent of field ordering.
     *
     * @param proofKey the EC key extracted from the holder proof JWT
     * @return {@code true} if the proof key matches one of the attested keys, {@code false} otherwise
     * @throws JOSEException if a thumbprint cannot be computed
     */
    public boolean containsKey(@NotNull JWK proofKey) throws JOSEException {
        var proofThumbprint = proofKey.toPublicJWK().computeThumbprint().toString();
        var rawAttestedKeys = claims.getClaim("attested_keys");

        if (!(rawAttestedKeys instanceof List<?> attestedKeyList) || attestedKeyList.isEmpty()) {
            return false;
        }

        for (var entry : attestedKeyList) {
            if (!(entry instanceof Map<?, ?> rawKey)) {
                throw new JOSEException("attested_keys entry is not a JSON object");
            }
            try {
                var attestedThumbprint = JWK.parse(toStringKeyMap(rawKey)).computeThumbprint().toString();
                if (proofThumbprint.equals(attestedThumbprint)) {
                    return true;
                }
            } catch (ParseException e) {
                throw new JOSEException("Failed to parse attested key entry: " + e.getMessage(), e);
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> toStringKeyMap(Map<?, ?> rawKey) {
        // Safe: JWTClaimsSet always deserialises JSON object keys as String
        return (Map<String, Object>) rawKey;
    }

    public String toJsonString() throws ParseException {
        if (signedJWT == null) {
            throw new IllegalStateException("Signed JWT is not initialized");
        }

        return this.getSignedJWT().getHeader().toString() + "." + this.getSignedJWT().getJWTClaimsSet().toString();
    }
}