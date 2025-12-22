package ch.admin.bj.swiyu.issuer.api.credentialofferstatus;

import lombok.Builder;

import java.util.UUID;

@Builder
public record CredentialOfferStatusResponseDto(
        UUID credentialOfferId,
        CredentialStatusTypeDto status
) {
}