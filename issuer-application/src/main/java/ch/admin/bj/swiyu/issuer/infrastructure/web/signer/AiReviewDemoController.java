package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

/**
 * TEMPORARY file to test the AI review pipeline. Contains deliberate violations. Do NOT merge.
 */
@Slf4j
@RestController
public class AiReviewDemoController {

    // Violation 1: field injection (instead of constructor injection) and mutable shared state in a singleton
    @Autowired
    private Environment environment;

    private final List<String> seenTokens = new ArrayList<>();

    @GetMapping("/demo/token")
    public String getToken(String token) {
        // Violation 2: logs a secret and mutates shared state without synchronization
        log.info("Received token {}", token);
        seenTokens.add(token);
        return token;
    }
}
