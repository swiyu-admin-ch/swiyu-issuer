/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.config;

import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import lombok.Data;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@Data
public class WebConfig implements WebMvcConfigurer {
    private final ApplicationProperties applicationProperties;

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new StringToEnumConverter());
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("https://confluence.bit.admin.ch")
                .allowedMethods("*");
    }

    static class StringToEnumConverter implements Converter<String, CredentialStatusTypeDto> {
        @Override
        public CredentialStatusTypeDto convert(String source) {
            return CredentialStatusTypeDto.valueOf(source.toUpperCase());
        }
    }
}
