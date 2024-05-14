package ch.admin.bit.eid.oid4vci.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "OID4VCI service",
                description = "Generic Issuer OID4VCI service",
                contact = @Contact(
                        email = "eid@bit.admin.ch",
                        name = "eID",
                        url = "https://confluence.eap.bit.admin.ch/display/YOUR_TEAM/"
                )
        )
)
public class OpenApiConfig { }
