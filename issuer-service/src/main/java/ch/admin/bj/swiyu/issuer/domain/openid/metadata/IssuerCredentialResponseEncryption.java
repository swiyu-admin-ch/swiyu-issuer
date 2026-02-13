package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Issuer encryption options / requirements for the credential response (sending the VC to the holder)
 */
@EqualsAndHashCode(callSuper = true)
@SuperBuilder
@Data
@Validated
@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
public class IssuerCredentialResponseEncryption extends IssuerCredentialEncryption {
    @JsonProperty("alg_values_supported")
    @NotEmpty
    @Valid
    @Builder.Default
    private List<@Pattern(regexp = "^ECDH-ES$") String> algValuesSupported = List.of("ECDH-ES");

    public boolean contains(CredentialResponseEncryptionClass requestedEncryption) {
        return algValuesSupported.contains(requestedEncryption.getAlg())
                && encValuesSupported.contains(requestedEncryption.getEnc());
    }
}
