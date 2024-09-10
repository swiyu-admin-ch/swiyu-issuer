package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import ch.admin.bit.eid.issuer_management.exceptions.ConfigurationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@AllArgsConstructor
public class RestService {
    public static final String CONTROLLER_URL_ADDITION = "/api/v1/statuslist/{datastoreEntryId}.jwt";
    private final RestClient restClient;

    public void updateStatusList(String uri, String statusListJWT) {
        String datastoreEntryId = null;
        final Pattern pattern = Pattern.compile("\\/(?<datastoreEntryId>[-\\w]*)\\.jwt");
        try {
            Matcher matcher = pattern.matcher(uri);
            matcher.find();
            datastoreEntryId = matcher.group("datastoreEntryId");
            restClient.put()
                    .uri(CONTROLLER_URL_ADDITION, datastoreEntryId)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(statusListJWT)
                    .retrieve()
                    .toBodilessEntity();
        } catch (IllegalArgumentException e) {
            log.warn(String.format("Extracting datastore entry from the status list uri %s using regex %s failed", uri, pattern));
            throw new BadRequestException(String.format("Status list URI %s can not be resolved", uri));
        } catch (RestClientException e) {
            log.error("Failed to update API endpoint", e);
            throw new ConfigurationException(String.format("Failed to update status list - does the status list %s exist?", datastoreEntryId));
        }
    }
    
}
