/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@Validated
public class CredentialDefinition {
    @NotNull
    private List<String> type;
    private Map<String, CredentialClaim> credentialSubject;
    /**
     * Required for JSON-LD, not existent for JWT
     */
    @JsonProperty("@context")
    private List<String> context;

    public List<String> getMandatoryClaims() {
        return credentialSubject.entrySet().stream()
                .filter(entry -> entry.getValue().isMandatory())
                .map(Map.Entry::getKey)
                .toList();
    }
}
