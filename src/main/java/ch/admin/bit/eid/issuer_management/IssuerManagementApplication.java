package ch.admin.bit.eid.issuer_management;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
@Slf4j
public class IssuerManagementApplication {

	public static void main(String[] args) {
		Environment env = SpringApplication.run(IssuerManagementApplication.class, args).getEnvironment();
		String appName = env.getProperty("spring.application.name");
		String serverPort = env.getProperty("server.port");
		log.info(
				"""
                        
                        ----------------------------------------------------------------------------
                        \t'{}' is running!\s
                        \tProfile(s): \t\t\t\t{}
                        \tSwaggerUI:   \t\t\t\thttp://localhost:{}/swagger-ui.html
                        ----------------------------------------------------------------------------""",
				appName,
				env.getActiveProfiles(),
				serverPort
		);
	}

}
