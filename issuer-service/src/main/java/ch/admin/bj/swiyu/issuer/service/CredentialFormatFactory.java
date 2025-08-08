/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CredentialFormatFactory {

    private final ApplicationProperties applicationProperties;
    private final IssuerMetadataTechnical issuerMetadata;
    private final DataIntegrityService dataIntegrityService;
    private final SdjwtProperties sdjwtProperties;
    private final SignatureService signatureService;
    private final StatusListRepository statusListRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;

    /**
     * Get the credential format builder for the given configuration identifier.
     * All values are allowed which are present in resources/example_issuer_metadata.json file
     *
     * @param configurationIdentifier unique identifier for credential profile
     */
    public CredentialBuilder getFormatBuilder(String configurationIdentifier) {
        var configuration = issuerMetadata.getCredentialConfigurationSupported().get(configurationIdentifier);
        if (configuration == null) {
            throw new IllegalArgumentException("Unknown configuration identifier: " + configurationIdentifier);
        }

        return switch (configuration.getFormat()) {
            case "vc+sd-jwt" -> {
                try {
                    yield new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, signatureService.createSigner(sdjwtProperties), statusListRepository, credentialOfferStatusRepository);
                } catch (Exception e) {
                    throw new ConfigurationException("Signing Key Configuration could not be used for signature", e);
                }
            }
            default -> throw new IllegalArgumentException("Unknown format: " + configuration.getFormat());
        };
    }
}