package ch.admin.bj.swiyu.issuer.management.it;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
class StatusListIT {

    private static final String BASE_URL = "/credentials";
    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusListUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt".formatted(statusListUUID);

    @Autowired
    protected SwiyuProperties swiyuProperties;

    @Autowired
    private MockMvc mvc;

    @MockBean
    private StatusBusinessApiApi statusBusinessApi;

    @Autowired
    private StatusListRepository statusListRepository;

    @BeforeEach
    void setUp() {
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusListUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(statusListEntryCreationDto);
    }

    @AfterEach
    void tearDown() {
        statusListRepository.deleteAll();
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}".formatted(RandomStringUtils.random(10), statusListUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }
}
