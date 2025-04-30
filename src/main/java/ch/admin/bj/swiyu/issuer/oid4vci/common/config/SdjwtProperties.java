/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.key.sdjwt")
@Slf4j
@Valid
@Getter
@Setter
public class SdjwtProperties {
    /**
     * Method of signing key management
     */
    private String keyManagementMethod;

    /**
     * Private Key, if the key is not managed by HSM
     * This includes vault or just mounted as environment variable
     */
    private String privateKey;
    /**
     * The id of the verification method in the did document with which a verifier can check the issued VC
     * In did tdw/webvc this is the full did#fragment
     */
    @NotEmpty
    private String verificationMethod;

    /**
     * The version of the sd-jwt schema
     */
    @NotEmpty
    private String version = "1.0";

    /**
     * Location of the config file, see the <a href="https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">official java documentation</a>
     */
    private String pkcs11Config;

    private HSMProperties hsm;

}
