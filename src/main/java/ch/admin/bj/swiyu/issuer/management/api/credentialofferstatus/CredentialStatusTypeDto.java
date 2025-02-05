/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
@Schema(name = "CredentialStatusType", enumAsRef = true, example = "SUSPENDED", description = """
            Status for the full lifecycle of a verifiable credential.
            OFFERED - an offer link has been created, and not yet redeemed by a holder.
            CANCELLED - the VC was revoked before being claimed.
            IN_PROGRESS - very short lived state, if the Holder has redeemed the one-time-code, but not yet gotten their credential. To allow a holder to retry fetching the vc set the state to offered.
            ISSUED - the VC has been collected by the holder and is valid.
            SUSPENDED - the VC has been temporarily suspended. To unsuspend change state to issued.
            REVOKED - the VC has been revoked. This state is final and can not be changed.
            EXPIRED - the lifetime of the VC expired (not used yet)
        """)
public enum CredentialStatusTypeDto {
    OFFERED,
    CANCELLED,
    IN_PROGRESS,
    ISSUED,
    SUSPENDED,
    REVOKED,
    EXPIRED;

    public boolean isIssuedToHolder() {
        return this != OFFERED && this != IN_PROGRESS && this != CANCELLED;
    }

    public boolean isDuringHolderInteraction() {
        return this == IN_PROGRESS;
    }
}
