/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import com.nimbusds.jose.JWSSigner;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class CredentialFormatFactory {

    private final ApplicationProperties applicationProperties;
    private final IssuerMetadataTechnical issuerMetadata;
    private final DataIntegrityService dataIntegrityService;
    private final SdjwtProperties sdjwtProperties;
    private final JWSSigner signer;

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
            case "vc+sd-jwt" ->
                    new SdJwtCredential(applicationProperties, issuerMetadata, dataIntegrityService, sdjwtProperties, signer);
            default -> throw new IllegalArgumentException("Unknown format: " + configuration.getFormat());
        };
    }
}
