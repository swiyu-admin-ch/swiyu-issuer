package ch.admin.bj.swiyu.issuer.dto.credentialofferstatus;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(name = "UpdateCredentialStatusRequestType", enumAsRef = true, example = "SUSPENDED", description = """
            Status for the full lifecycle of a verifiable credential.
            CANCELLED - the VC was revoked before being claimed.
            READY - Status set by the business issuer to continue the issuance of the credential for the deferred flow
            SUSPENDED - the VC has been temporarily suspended. To unsuspend change state to issued.
            REVOKED - the VC has been revoked. This state is final and can not be changed.
        """)
public enum UpdateCredentialStatusRequestTypeDto {

    CANCELLED,
    READY,
    ISSUED,
    SUSPENDED,
    REVOKED
}