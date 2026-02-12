package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Schema(name = "ProofType")
public enum ProofTypeDto {
    JWT("jwt", "openid4vci-proof+jwt");

    private final String displayName;
    /**
     * REQUIRED "typ": claim
     */
    private final String claimTyp;
}