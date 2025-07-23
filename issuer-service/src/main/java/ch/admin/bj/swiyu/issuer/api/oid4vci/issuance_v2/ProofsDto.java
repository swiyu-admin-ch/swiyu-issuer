package ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

/**
 * ProofsDto represents the proofs object in the OID4VCI Credential Request.
 * TODO At the moment only the jwt part is implemented
 *
 * @param jwt see: <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof-types">...</a>
 */
public record ProofsDto(
        @NotEmpty
        @Schema(description = """
                ProofsDto represents the proofs object in the OID4VCI Credential Request.
                """, example = """
                "jwt": [
                   "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwidXNlIjoic2lnIiwiY3J2IjoiUC0yNTYiLCJraWQiOiJUZXN0LUtleSIsIngiOiJrdHFJRFpoUjFmY2NlM3VGanpxdDdLRVlEdVdweFJoX3pqdkszanZsS2k4IiwieSI6Ik1UV2ZObTJ6dy1CbklqM2szbW0xZVB3Q3hqTm9DSEowdXN6V25MeHVDemsiLCJpYXQiOjE3NTMyNjkyNzZ9fQ.eyJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvb2lkNHZjaSIsIm5vbmNlIjoiY2U5YzEzNzgtODc2Yi00OGUyLTg0ZmUtOGE0ZjUwZGFkZmJmIiwiaWF0IjoxNzUzMjY5Mjc2fQ.ck-6Oq6IAav1VdFOkq9Qh7tzrl52jJvFBU3aPcZ_20oE73Cf4izN0ECmmiJm_qUMvYJlykQFsX2sW43gFC6vCw".
                   "..."
                ]
                """)
        List<String> jwt
) {
}