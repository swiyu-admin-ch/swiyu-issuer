package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;

import java.util.UUID;

public record OfferStateChangeEvent(UUID credentialManagementId, UUID credentialOfferId, CredentialOfferStatusType newState) {
}