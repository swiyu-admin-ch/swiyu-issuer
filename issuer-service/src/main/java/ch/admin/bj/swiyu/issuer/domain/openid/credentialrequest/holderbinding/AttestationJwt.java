package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.jwtvalidator.DidKidParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.util.Date;
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
        validateHeader(parsedJwt.getHeader(), enforceSwissProfileVersioning);
        validateBody(claims);
        return new AttestationJwt(parsedJwt, extractSupportedAttackPotentialResistance(claims));
    }

    /**
     * Validates required claims of the attestation JWT body.
     * Note: the {@code iss} claim is intentionally not validated here – per PARENT-ADR-027
     * the {@code iss} claim is optional and ignored; trust is established exclusively via the {@code kid}.
     *
     * @param jwtClaimsSet The JWT body to be checked
     * @throws IllegalArgumentException if a required claim is missing or invalid
     */
    private static void validateBody(JWTClaimsSet jwtClaimsSet) throws IllegalArgumentException {
        if (jwtClaimsSet.getIssueTime() == null) {
            throw new IllegalArgumentException("IssueTime is required");
        }
        var expirationTime = jwtClaimsSet.getExpirationTime();
        if (expirationTime == null) {
            throw new IllegalArgumentException("ExpirationTime is required");
        }
        if (expirationTime.before(new Date())) {
            throw new IllegalArgumentException("Attestation is expired");
        }
        if (jwtClaimsSet.getClaim("attested_keys") == null) {
            throw new IllegalArgumentException("attested_keys is required");
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
    static void validateHeader(JWSHeader header, boolean enforceSwissProfileVersioning) {

        validateType(header);

        validateAlgorithm(header);

        if (enforceSwissProfileVersioning) {
            validateSwissProfileVersion(header);
        }
    }

    private static void validateType(JWSHeader header) {
        var type = header.getAlgorithm();
        if (type == null || !ALLOWED_TYPES.contains(header.getType().getType())) {
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
     * Verifies that the attestation provider DID – derived from the {@code kid} in the JWT header –
     * is contained in the list of trusted attestation providers.
     *
     * <p>Per PARENT-ADR-027 the {@code iss} claim is ignored; trust is established exclusively
     * via the {@code kid}. The DID is extracted from the absolute {@code kid} (DID URL with
     * {@code #} fragment) using {@link DidKidParser#getDidFromAbsoluteKid(String)}.</p>
     *
     * @param trustedAttestationProviders list of trusted attestation provider DID strings
     * @throws IllegalArgumentException if the kid-derived DID is not in the trusted list
     */
    public void throwIfNotTrustedAttestationProvider(@NotNull List<String> trustedAttestationProviders) throws IllegalArgumentException {
        String kid = signedJWT.getHeader().getKeyID();
        String did = new DidKidParser().getDidFromAbsoluteKid(kid);
        if (!trustedAttestationProviders.contains(did)) {
            throw new IllegalArgumentException(
                    "The attestation provider DID %s is not in the list of trusted attestation providers %s."
                            .formatted(did, String.join(", ", trustedAttestationProviders)));
        }
    }

    /**
     * Checks whether the attested attack potential resistance satisfies the required resistance levels.
     *
     * <p>Signature verification is handled externally by the service layer via
     * {@code DidJwtValidator} before this method is called.</p>
     *
     * @param resistance the required {@link AttackPotentialResistance} levels; if empty, any
     *                   attestation is considered valid
     * @return {@code true} if the attested resistance matches at least one required level,
     *         or if {@code resistance} is empty
     */
    public boolean isValidAttestation(@NotNull List<AttackPotentialResistance> resistance) {
        if (resistance.isEmpty()) {
            return true;
        }
        var providedResistanceSet = new HashSet<>(attestedAttackPotentialResistance);
        providedResistanceSet.retainAll(resistance);
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
    public boolean containsKey(@NotNull ECKey proofKey) throws JOSEException {
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