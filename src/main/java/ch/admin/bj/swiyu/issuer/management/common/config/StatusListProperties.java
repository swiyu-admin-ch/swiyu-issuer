/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.common.config;

import ch.admin.bj.swiyu.issuer.management.common.exception.ConfigurationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Slf4j
@Configuration
@Validated
@Data
@ConfigurationProperties(prefix = "application.status-list")
public class StatusListProperties {
    private String privateKey;
    private JWK statusListKey;
    private String verificationMethod;
    @NotNull
    private String keyManagementMethod;
    private HSMProperties hsm;
    private int statusListSizeLimit;

    private String version = "1.0";

    @PostConstruct
    public void init() {
        try {
            statusListKey = JWK.parseFromPEMEncodedObjects(privateKey);
        } catch (JOSEException e) {
            log.error("Status List Signing key can not be parsed", e);
            throw new ConfigurationException("Status List Signing key can not be parsed");
        }
    }
}
