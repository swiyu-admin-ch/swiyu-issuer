package ch.admin.bj.swiyu.issuer.management.infrastructure.web.config;

import ch.admin.bj.swiyu.issuer.management.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusType;
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

    static class StringToEnumConverter implements Converter<String, CredentialStatusType> {
        @Override
        public CredentialStatusType convert(String source) {
            return CredentialStatusType.valueOf(source.toUpperCase());
        }
    }
}
