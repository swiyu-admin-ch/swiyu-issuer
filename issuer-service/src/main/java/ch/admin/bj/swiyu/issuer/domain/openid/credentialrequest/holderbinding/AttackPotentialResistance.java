package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;

/**
 * Values as defined in ISO 18045 and used in
 * <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-attack-potential-resistance">OID4VCI Attack Potential Resistance</a>
 * <br>
 * <b>Note: Urls currently not supported</b><br>
 * When ISO 18045 is not used, ecosystems may define their own values.
 * If the value does not map to a well-known specification,
 * it is RECOMMENDED that the value is a URL that gives further information
 * about the attack potential resistance and possible relations to level of assurances
 */
@JsonFormat(shape = JsonFormat.Shape.STRING)
public enum AttackPotentialResistance {
    ISO_18045_HIGH("iso_18045_high"),
    // Not yet supported
    //    ISO_18045_MODERATE("iso_18045_moderate"),
    //    ISO_18045_BASIC("iso_18045_basic"),
    ISO_18045_ENHANCED_BASIC("iso_18045_enhanced-basic");


    private final String value;

    AttackPotentialResistance(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return getValue();
    }

    /**
     * Parses the AttackPotentialResistance using the value, instead of the java enum string which can not have dashes (-)
     * @param parseValue to be parsed into an AttackPotentialResistance object
     * @return the AttackPotentialResistance with matching value
     * @throws IllegalArgumentException if the value could not be parsed
     */
    public static AttackPotentialResistance parse(String parseValue) throws IllegalArgumentException {
        return Arrays.stream(AttackPotentialResistance.values())
                .filter(a -> a.getValue().equals(parseValue))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(String.format("%s is no valid AttackPotentialResistance", parseValue)));

    }
}
