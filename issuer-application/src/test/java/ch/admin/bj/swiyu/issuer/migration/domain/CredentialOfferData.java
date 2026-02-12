package ch.admin.bj.swiyu.issuer.migration.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@AllArgsConstructor
@Getter
@Setter
public class CredentialOfferData {
    private UUID id;
    private String offerStatus;
    private UUID accessToken;
    private UUID refreshToken;
    private String dpopKey;
    private Long tokenExpirationTimestamp;
    private UUID metadataTenantId;
    private UUID credentialManagementId;

    public CredentialOfferData(UUID id, String offerStatus, UUID accessToken, UUID refreshToken, String dpopKey, Long tokenExpirationTimestamp) {
        this.id = id;
        this.offerStatus = offerStatus;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.dpopKey = dpopKey;
        this.tokenExpirationTimestamp = tokenExpirationTimestamp;
        this.metadataTenantId = UUID.randomUUID();
        this.credentialManagementId = null;
    }
}
