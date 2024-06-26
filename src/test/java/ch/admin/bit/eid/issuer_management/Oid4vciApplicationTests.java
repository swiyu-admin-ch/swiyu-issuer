package ch.admin.bit.eid.issuer_management;

import ch.admin.bit.eid.issuer_management.controllers.CredentialsController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class IssuerManagementApplicationTests {

	@Autowired
	private CredentialsController credentialsController;

	@Test
	void contextLoads() {
		assertThat(credentialsController).isNotNull();
	}

}
