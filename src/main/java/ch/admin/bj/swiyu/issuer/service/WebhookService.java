package ch.admin.bj.swiyu.issuer.infrastructure.callback;

import ch.admin.bj.swiyu.issuer.infrastructure.config.WebhookProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OutboxService {
    private final WebhookProperties webhookProperties;
    private final CallbackEventRepository callbackEventRepository;

}
