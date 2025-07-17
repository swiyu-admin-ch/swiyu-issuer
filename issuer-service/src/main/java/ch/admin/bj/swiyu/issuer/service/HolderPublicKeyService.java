package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class HolderPublicKeyService {

    private final KeyAttestationService keyAttestationService;
    private final OpenIdIssuerConfiguration openIDConfiguration;
    private final IssuerMetadataTechnical issuerMetadata;
    private final ApplicationProperties applicationProperties;
    private final NonceService nonceService;
}