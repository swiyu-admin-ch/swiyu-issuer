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
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;

@Slf4j
@Service
@AllArgsConstructor
public class BusinessIssuerRenewalApiClient {

    private final WebClient webClient;
    private final ApplicationProperties applicationProperties;

    @Transactional
    public RenewalResponseDto getRenewalData(RenewalRequestDto requestDto) {

        return webClient.post()
                .uri(URI.create(applicationProperties.getBusinessIssuerRenewalApiEndpoint()))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestDto)
                .retrieve()
                .onStatus(HttpStatusCode::isError, response -> {
                    log.error("Renewal request to {} failed with status code {}",
                            applicationProperties.getBusinessIssuerRenewalApiEndpoint(), response.statusCode());
                    return reactor.core.publisher.Mono.error(new RenewalException(HttpStatus.valueOf(response.statusCode().value()), "Renewal request failed"));
                })
                .bodyToMono(RenewalResponseDto.class)
                .block();
    }
}