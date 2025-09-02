package ch.admin.bj.swiyu.issuer.service.webhook;

import java.util.UUID;

public record DeferredEvent(UUID credentialOfferId, String clientAgentInfo) {
}