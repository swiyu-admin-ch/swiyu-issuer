/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.api.credentialofferstatus;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(name = "CredentialStatusType", enumAsRef = true, example = "SUSPENDED", description = """
            Status for the full lifecycle of a verifiable credential.
            OFFERED - an offer link has been created, and not yet redeemed by a holder.
            CANCELLED - the VC was revoked before being claimed.
            IN_PROGRESS - very short lived state, if the Holder has redeemed the one-time-code, but not yet gotten their credential. To allow a holder to retry fetching the vc set the state to offered.
            DEFERRED - the offer has been used and all necessary data from the wallet has been received but the credential is not yet issued. To use this state the credential metadata entry has to have deferred set to true.
            READY - Status set by the business issuer to continue the issuance of the credential for the deferred flow.
            ISSUED - the VC has been collected by the holder and is valid.
            SUSPENDED - the VC has been temporarily suspended. To unsuspend change state to issued.
            REVOKED - the VC has been revoked. This state is final and can not be changed.
            EXPIRED - the lifetime of the VC expired (not used yet)
        """)
public enum CredentialStatusTypeDto {
    OFFERED,
    CANCELLED,
    IN_PROGRESS,
    DEFERRED,
    READY,
    ISSUED,
    SUSPENDED,
    REVOKED,
    EXPIRED
}