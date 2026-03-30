package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.List;

public class PathElementsValidator implements ConstraintValidator<ValidPathElements, List<?>> {

    @Override
    public boolean isValid(List<?> value, ConstraintValidatorContext context) {

        // must be a non-empty array
        if (value == null || value.isEmpty()) {
            return false; // MUST be a non-empty array
        }

        for (Object o : value) {
            switch (o) {
                case null -> {
                    // is valid, continue
                }
                case String ignored -> {
                    // is valid, continue
                }
                case Number n when isValidNumber(n) -> {
                    // is valid, continue
                }
                default -> {
                    return false; // invalid type
                }
            }
        }
        return true;
    }

    private boolean isValidNumber(Number n) {
        double d = n.doubleValue();

        // get the number without any decimals
        long l = n.longValue();

        // Double allows infinite numbers and NaN which are not valid integers
        if (!Double.isFinite(d) || Double.isNaN(d)) return false; // not an integer

        // check if the double value is equal to the long value, which means it's an integer
        // check if non-negative integer
        return d == l && l >= 0;
    }
}