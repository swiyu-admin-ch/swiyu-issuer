package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.List;

public class ClaimPathPointerValidator implements ConstraintValidator<ValidPathElements, List<?>> {

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
                case Number n when n.intValue() == Math.abs(n.doubleValue()) -> {
                    // is valid, continue
                }
                default -> {
                    return false; // invalid type
                }
            }
        }
        return true;
    }
}