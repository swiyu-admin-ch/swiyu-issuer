/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.common.config;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URL;
import java.time.Duration;
import java.util.UUID;

@Validated
@ConfigurationProperties(prefix = "swiyu")
public record SwiyuProperties(
        @NotNull RegistryProperties statusRegistry,
        @NotNull UUID businessPartnerId) {
    public record RegistryProperties(
            @NotNull URL apiUrl,
            @NotNull URL tokenUrl,
            @NotNull Duration tokenRefreshInterval,
            @Size(min = 1) // workaround as we want to allow null bit not empty strings.
            // See:https://stackoverflow.com/questions/31132477/java-annotation-for-null-but-neither-empty-nor-blank
            String bootstrapRefreshToken,
            @NotNull Boolean enableRefreshTokenFlow,
            @NotEmpty @NotNull String customerKey,
            @NotEmpty @NotNull String customerSecret) {
    }
}
