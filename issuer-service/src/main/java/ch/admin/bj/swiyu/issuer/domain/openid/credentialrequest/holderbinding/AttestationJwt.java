package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
public final class AttestationJwt {

    @Deprecated(since = "OID4VCI 1.0")
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
     * @return a AttestationJwt
     * @throws ParseException if the JWT is malformed (not a valid JWT)
     */
    public static AttestationJwt parseJwt(String jwt) throws ParseException {
        var parsedJwt = SignedJWT.parse(jwt);
        var claims = parsedJwt.getJWTClaimsSet();
        // Check required Headers & Payload
        validateHeader(parsedJwt.getHeader());
        validateBody(claims);
        // Validation between Header and body
        if (!parsedJwt.getHeader().getKeyID().split("#")[0].equals(claims.getIssuer())) {
            throw new IllegalArgumentException("The key id must conform to the did syntax (did:webvh ...)");
        }
        return new AttestationJwt(parsedJwt, extractSupportedAttackPotentialResistance(claims));
    }

    /**
     * @param jwtClaimsSet The JWT Body to be checked for Attestation JWT Required attributes
     * @throws IllegalArgumentException if one of the checks fails
     */
    private static void validateBody(JWTClaimsSet jwtClaimsSet) throws IllegalArgumentException {
        if (StringUtils.isEmpty(jwtClaimsSet.getIssuer())) {
            throw new IllegalArgumentException("Issuer is required");
        }
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
     * @param header The JWSHeader to be checked for Attestation JWT Required attributes
     * @throws IllegalArgumentException if one of the checks fails
     */
    private static void validateHeader(JWSHeader header) throws IllegalArgumentException {

        var type = header.getAlgorithm();
        if (type == null || !ALLOWED_TYPES.contains(header.getType().getType())) {
            throw new IllegalArgumentException("Typ must be one of " + String.join(", ", ALLOWED_TYPES));
        }

        var algorithm = header.getAlgorithm();
        if (algorithm == null || !ALLOWED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Algorithm must be one of "
                    + ALLOWED_ALGORITHMS.stream().map(JWSAlgorithm::getName).collect(Collectors.joining(", ")));
        }
        if (StringUtils.isEmpty((header.getKeyID()))) {
            throw new IllegalArgumentException("KeyID MUST be set");
        }
    }

    /**
     * @param trustedAttestationProviders list of trusted issuers
     * @throws IllegalArgumentException if the issuer of the jwt is not matching the list of trusted attestation providers
     */
    public void throwIfNotTrustedAttestationProvider(@NotNull List<String> trustedAttestationProviders) throws IllegalArgumentException {
        if (!trustedAttestationProviders.contains(claims.getIssuer())) {
            throw new IllegalArgumentException("The JWT issuer %s is not in the list of trusted issuers %s.".formatted(claims.getIssuer(), String.join(", ", trustedAttestationProviders)));
        }
    }

    /**
     * @param keyResolver service to resolve the public JWK with
     * @param resistance  Which resistance must be attested
     * @return true if the attestation is valid and the resistance is matching
     * @throws JOSEException if the fetched Key can not be parsed as a supported JWSVerifier
     */
    public boolean isValidAttestation(@NotNull KeyResolver keyResolver, @NotNull List<AttackPotentialResistance> resistance) throws JOSEException {
        var header = signedJWT.getHeader();
        var key = keyResolver.resolveKey(header.getKeyID());
        if (!signedJWT.verify(new ECDSAVerifier(key.toECKey()))) {
            throw new JOSEException("JWT verification failed");
        }
        if (resistance.isEmpty()) {
            return true;
        }
        var providedResistanceSet = new HashSet<>(attestedAttackPotentialResistance);
        providedResistanceSet.retainAll(resistance);
        // We only care IF we have a matching resistance spec
        return !providedResistanceSet.isEmpty();
    }

    public String toJsonString() throws ParseException {
        if (signedJWT == null) {
            throw new IllegalStateException("Signed JWT is not initialized");
        }

        return this.getSignedJWT().getHeader().toString() + "." + this.getSignedJWT().getJWTClaimsSet().toString();
    }
}