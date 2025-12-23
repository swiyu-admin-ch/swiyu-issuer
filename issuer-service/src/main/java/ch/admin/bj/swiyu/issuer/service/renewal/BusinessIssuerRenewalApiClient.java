package ch.admin.bj.swiyu.issuer.service.renewal;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.URI;

@Slf4j
@Service
@AllArgsConstructor
public class BusinessIssuerRenewalApiClient {

    private final RestClient restClient;
    private final ApplicationProperties applicationProperties;

    @Transactional
    public RenewalResponseDto getRenewalData(RenewalRequestDto requestDto) {

        try {
        return restClient.post()
                .uri(URI.create(applicationProperties.getBusinessIssuerRenewalApiEndpoint()))
                .body(requestDto)
                .contentType(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(HttpStatusCode::isError, (request, response) -> {
                    log.error("Renewal request to {} failed with status code {} with message {}",
                            applicationProperties.getBusinessIssuerRenewalApiEndpoint(), request.getURI(), response.getStatusCode());
                    throw new RenewalException(HttpStatus.valueOf(response.getStatusCode().value()), "Renewal request failed");
                })
                .body(RenewalResponseDto.class);
        } catch (RestClientResponseException e) {
            log.error("Renewal request to {} failed with status code {} with message {}",
                    applicationProperties.getBusinessIssuerRenewalApiEndpoint(), e.getStatusCode(), e.getMessage());
        } catch (RenewalException e) {
            log.error("Renewal request failed: {}", e.getMessage());
        }
        return null;
    }
}