package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;

import java.util.UUID;

public record StateChangeEvent(UUID credentialOfferId, CredentialStatusType newState) {
}