package ch.admin.bj.swiyu.issuer.infrastructure.env;

import ch.admin.bj.swiyu.issuer.infrastructure.config.ActuatorEnvProperties;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.SanitizingFunction;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * ActuatorSanitizer to restrict the information provided on  the /actuator/env endpoint.
 * It works through a whitelist of values set in the config, which are allowed.
 * However, there's also a blacklist, which takes priority over the whitelist.
 */
@Component
public class ActuatorSanitizer implements SanitizingFunction {
    private static final String[] REGEX_PARTS = {"*", "$", "^", "+"};
    private static final Set<String> keysToSanitize = Set.of("password", "secret", "token");
    private final List<Pattern> whitelist = new ArrayList<>();
    private final List<Pattern> blacklist = new ArrayList<>();


    public ActuatorSanitizer(ActuatorEnvProperties properties) {
        List<String> allowedProperties = properties.getAllowedProperties();
        for (String key : allowedProperties) {
            this.whitelist.add(getPattern(key));
        }
        for (String key : keysToSanitize) {
            this.blacklist.add(getPattern(key));
        }
    }

    @Override
    public SanitizableData apply(SanitizableData data) {
        if (data.getValue() == null) {
            return data;
        }

        for (Pattern pattern : this.blacklist) {
            if (pattern.matcher(data.getKey()).matches()) {
                return data.withSanitizedValue();
            }
        }

        for (Pattern pattern : this.whitelist) {
            if (pattern.matcher(data.getKey()).matches()) {
                return data;
            }
        }

        return data.withSanitizedValue();
    }

    private Pattern getPattern(String value) {
        if (isRegex(value)) {
            return Pattern.compile(value, Pattern.CASE_INSENSITIVE);
        }
        return Pattern.compile(".*" + Pattern.quote(value) + "$", Pattern.CASE_INSENSITIVE);
    }

    private boolean isRegex(String value) {
        for (String part : REGEX_PARTS) {
            if (value.contains(part)) {
                return true;
            }
        }
        return false;
    }
}