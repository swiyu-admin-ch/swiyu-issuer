package ch.admin.bit.eid.issuer_management.it;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

// TODO EID-1736: remove inheritance complexity from tests:
//  e.g. https://medium.com/@cezar.opri/we-should-avoid-using-inheritance-in-our-tests-7e900349b0b4
@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class BaseIt {

    @Autowired
    protected MockMvc mvc;

    protected static final String BASE_URL = "/credentials";
}
