package ch.admin.bj.swiyu.issuer.common.config;

import jakarta.validation.Valid;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.annotation.Configuration;

@Configuration
@Valid
@Getter
@Setter
public class HSMProperties {
    private String userPin;
    private String keyId;
    private String keyPin;
    private String pkcs11Config;

    private String user;
    private String host;
    private String port;
    private String password;

    private String proxyUser;
    private String proxyPassword;
}
