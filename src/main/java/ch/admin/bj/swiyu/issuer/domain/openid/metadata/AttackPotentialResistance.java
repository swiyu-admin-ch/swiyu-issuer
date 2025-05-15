package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonValue;

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
    iso_18045_high("iso_18045_high"),
    iso_18045_moderate("iso_18045_moderate"),
    iso_18045_enhanced_basic("iso_18045_enhanced-basic"),
    iso_18045_basic("iso_18045_basic");

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
}
