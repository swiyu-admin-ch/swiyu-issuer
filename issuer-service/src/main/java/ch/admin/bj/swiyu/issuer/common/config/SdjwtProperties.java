package ch.admin.bj.swiyu.issuer.common.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;


@Slf4j
@Validated
@Getter
@Setter
@ConfigurationProperties(prefix = "application.key.sdjwt")
public class SdjwtProperties extends SignatureConfiguration {

}
