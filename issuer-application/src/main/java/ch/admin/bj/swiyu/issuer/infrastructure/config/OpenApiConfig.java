/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.dto.callback.WebhookCallbackDto;
import ch.admin.bj.swiyu.issuer.dto.exception.ApiErrorDto;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.AllArgsConstructor;
import org.springdoc.core.customizers.GlobalOpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

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
        var additionalSchemas = Map.of("WebhookCallback", ModelConverters.getInstance().readAllAsResolvedSchema(WebhookCallbackDto.class).schema,
                "ApiError", ModelConverters.getInstance().readAllAsResolvedSchema(ApiErrorDto.class).schema);
        return openApi -> openApi.getComponents().getSchemas().putAll(additionalSchemas);
    }
}