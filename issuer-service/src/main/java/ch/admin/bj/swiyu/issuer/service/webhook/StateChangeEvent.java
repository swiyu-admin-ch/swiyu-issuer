package ch.admin.bj.swiyu.issuer.service.webhook;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;

import java.util.UUID;

public record StateChangeEvent(UUID credentialOfferId, CredentialStatusManagementType newState) {
}