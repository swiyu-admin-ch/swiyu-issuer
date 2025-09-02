/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.api.callback.WebhookCallbackDto;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.AllArgsConstructor;
import org.springdoc.core.customizers.GlobalOpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
@SecurityScheme(
        name = "bearer-jwt",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
public class OpenApiConfig {

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("Issuer Service API")
                .description("Generic swiyu Issuer Service service")
        );
    }

    @Bean
    GroupedOpenApi api() {
        return GroupedOpenApi.builder()
                .group("API")
                .pathsToMatch("/**")
                .build();
    }

    @Bean
    public GlobalOpenApiCustomizer openApiCustomizer() {
        return openApi -> openApi.getComponents().getSchemas().put("WebhookCallback",
                ModelConverters.getInstance().readAllAsResolvedSchema(WebhookCallbackDto.class).schema);
    }
}