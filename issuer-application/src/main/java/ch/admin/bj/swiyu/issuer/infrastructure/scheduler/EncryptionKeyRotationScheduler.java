package ch.admin.bj.swiyu.issuer.infrastructure.scheduler;

import ch.admin.bj.swiyu.issuer.service.enc.EncryptionKeyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduler component responsible for periodically rotating encryption keys.
 * Triggers the encryption key rotation process at a fixed interval and logs when a new key is generated.
 * The interval is configured via the application property {@code application.encryption-key-rotation-interval}.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class EncryptionKeyRotationScheduler {


    private final EncryptionKeyService encryptionKeyService;

    /**
     * Performs a key rotation for the encryption keys, replacing the currently active key set,
     * and logs when a new key has been generated.
     * Will keep one time unit of deprecated keys to prevent race conditions with credential requests.
     */
    @Scheduled(initialDelay = 0, fixedDelayString = "${application.encryption-key-rotation-interval}")
    @SchedulerLock(name = "rotateEncryptionKeys")
    public void rotateEncryptionKeys() {
        log.debug("Encryption Key rotation triggered");
        boolean newKeyGenerated = encryptionKeyService.rotateEncryptionKeys();
        if (newKeyGenerated) {
            log.info("New encryption keys generated");
        }
    }

}
