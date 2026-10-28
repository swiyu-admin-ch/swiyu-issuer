package ch.admin.bj.swiyu.issuer.service.renewal;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalRequestDto;
import ch.admin.bj.swiyu.issuer.dto.renewal.RenewalResponseDto;
import io.micrometer.common.util.StringUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.util.Set;

@Slf4j
@Service
@AllArgsConstructor
public class BusinessIssuerRenewalApiClient {

    /**
     * Error status codes for which a failed renewal is an expected outcome in normal operation, e.g. because the
     * credential to renew is already gone or unavailable, or because the business issuer is temporarily unable to
     * answer. For example:
     * <ul>
     *   <li>{@code 404} - the credential to renew is unknown as the managementId is not found</li>
     *   <li>{@code 409} - the renewal request conflicts with the current state at the business issuer (for example DPoP)</li>
     *   <li>{@code 420} - the business issuer reports that renewal quota is exceeded</li>
     *   <li>{@code 451} - the credential is unavailable for legal reasons</li>
     *   <li>{@code 500} - the business issuer failed to process the renewal request</li>
     *   <li>{@code 503} - the business issuer is temporarily unavailable</li>
     * </ul>
     *
     * Additional details can be found in the <a href="https://github.com/swiyu-admin-ch/swiyu-issuer/blob/main/docs/Architecture_generic_issuer.pdf">Architecture docs</a>
     */
    private static final Set<Integer> STATUS_CODES_LOGGED_AS_INFO = Set.of(404, 409, 420, 451, 500, 503);

    private final WebClient webClient;
    private final ApplicationProperties applicationProperties;

    @Transactional
    public RenewalResponseDto getRenewalData(RenewalRequestDto requestDto) {

        try {
            WebClient.RequestBodySpec request = webClient.post()
                    .uri(URI.create(applicationProperties.getBusinessIssuerRenewalApiEndpoint()));
            request = withApiKey(request);

            return request
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestDto)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, response -> {
                        logRenewalFailure(response.statusCode());
                        return reactor.core.publisher.Mono.error(new RenewalException(response.statusCode(), "Renewal request failed"));
                    })
                    .bodyToMono(RenewalResponseDto.class)
                    .block();
        } catch (RestClientResponseException e) {
            logRenewalFailure(e.getStatusCode(), e.getMessage());
            throw new RenewalException(e.getStatusCode(), "Renewal request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Logs a failed renewal request without a detailed message.
     *
     * @param statusCode the status code returned by the business issuer
     */
    private void logRenewalFailure(HttpStatusCode statusCode) {
        logRenewalFailure(statusCode, null);
    }

    /**
     * Logs a failed renewal request. The log level depends on the returned status code: expected failures are logged
     * at {@code INFO}, all others at {@code ERROR}.
     *
     * @param statusCode    status code returned by the business issuer
     * @param detailMessage additional, optional message
     */
    private void logRenewalFailure(HttpStatusCode statusCode, String detailMessage) {
        final var endpoint = applicationProperties.getBusinessIssuerRenewalApiEndpoint();
        final var logPrefix = "Renewal request to %s failed with status code %s".formatted(endpoint, statusCode);
        final var message = detailMessage == null
                ? logPrefix
                : "%s with message %s".formatted(logPrefix, detailMessage);

        if (STATUS_CODES_LOGGED_AS_INFO.contains(statusCode.value())) {
            log.info(message);
        } else {
            log.error(message);
        }
    }

    private WebClient.RequestBodySpec withApiKey(WebClient.RequestBodySpec request) {
        var apiKeyHeader = applicationProperties.getBusinessIssuerRenewalApiKeyHeader();
        var apiKey = applicationProperties.getBusinessIssuerRenewalApiKeyValue();
        if (!StringUtils.isBlank(apiKeyHeader) && !StringUtils.isBlank(apiKey)) {
            return request.header(apiKeyHeader, apiKey);
        }
        return request;
    }
}