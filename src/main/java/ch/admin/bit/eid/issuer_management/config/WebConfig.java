package ch.admin.bit.eid.issuer_management.config;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import lombok.Data;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@Data
public class WebConfig implements WebMvcConfigurer {
    private final ApplicationConfig appConfig;
    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(new StringToEnumConverter());
    }

    static class StringToEnumConverter implements Converter<String, CredentialStatusEnum> {
        @Override
        public CredentialStatusEnum convert(String source) {
            return CredentialStatusEnum.valueOf(source.toUpperCase());
        }
    }
}
