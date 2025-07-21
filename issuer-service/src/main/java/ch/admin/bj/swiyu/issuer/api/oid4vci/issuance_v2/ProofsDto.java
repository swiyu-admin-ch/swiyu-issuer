package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import jakarta.validation.constraints.NotEmpty;

import java.util.List;

// TODO check if other proof types are needed

/**
 * ProofsDto represents the proofs object in the OID4VCI Credential Request.
 *
 * @param jwt see: <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof-types">...</a>
 */
public record ProofsDto(
        @NotEmpty
        List<String> jwt
) {
}