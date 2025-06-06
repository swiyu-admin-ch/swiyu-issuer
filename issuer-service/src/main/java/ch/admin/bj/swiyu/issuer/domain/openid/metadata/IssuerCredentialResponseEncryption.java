/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Data
@Validated
public class IssuerCredentialResponseEncryption {
    @JsonProperty("alg_values_supported")
    @NotNull
    @Valid
    private List<@Pattern(regexp = "^(RSA-OAEP-256|ECDH-ES\\+A128KW)$") String> algValuesSupported;
    @JsonProperty("enc_values_supported")
    @NotNull
    private List<@Pattern(regexp = "^A128CBC-HS256$") String> encValuesSupported;
    @JsonProperty("encryption_required")
    @NotNull
    private boolean encRequired;

    public boolean contains(CredentialResponseEncryptionClass requestedEncryption) {
        return algValuesSupported.contains(requestedEncryption.getAlg())
                && encValuesSupported.contains(requestedEncryption.getEnc());
    }
}
