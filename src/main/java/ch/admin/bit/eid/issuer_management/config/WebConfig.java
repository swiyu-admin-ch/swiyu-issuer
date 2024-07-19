package ch.admin.bit.eid.issuer_management.config;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.interceptor.AuthInterceptorJWT;
import lombok.Data;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.text.ParseException;

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

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        WebMvcConfigurer.super.addInterceptors(registry);
        if (appConfig.isEnableJwtAuthentication()) {
            try {
                registry.addInterceptor(new AuthInterceptorJWT(appConfig.getWhitelistedKeySet()));
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }


}
