package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.LinkedList;
import java.util.List;

/**
 * Object that describes the requirement for key attestations as described in
 * <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestations">Appendix D</a>,
 * which the Credential Issuer expects the Wallet to send within the proof of the Credential Request.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeyAttestationRequirement {

    /**
     * Array defining values specified in
     * <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestations">Appendix D.2</a>
     * accepted by the Credential Issuer
     */
    @Nullable
    @JsonProperty("key_storage")
    private List<AttackPotentialResistance> keyStorage;


    @NotNull
    public List<AttackPotentialResistance> getKeyStorage() {
        if (keyStorage == null) {
            return new LinkedList<>();
        }
        return keyStorage;
    }
}
