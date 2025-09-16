package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialOfferMetadata(
        Boolean deferred,
        String vctIntegrity
) {
}