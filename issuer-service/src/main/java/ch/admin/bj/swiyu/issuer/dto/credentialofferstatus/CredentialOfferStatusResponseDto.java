package ch.admin.bj.swiyu.issuer.dto.credentialofferstatus;

import lombok.Builder;

import java.util.UUID;

@Builder
public record CredentialOfferStatusResponseDto(
        UUID credentialOfferId,
        CredentialStatusTypeDto status
) {
}