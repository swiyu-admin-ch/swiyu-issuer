package ch.admin.bj.swiyu.issuer.dto.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

import static java.util.Objects.isNull;

@RequiredArgsConstructor
public class ValidStatusListMaxLengthValidator implements ConstraintValidator<ValidStatusListMaxLength, Object> {

    private final StatusListProperties statusListProperties;

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext constraintValidatorContext) {

        var statusListCreateDto = (StatusListCreateDto) value;

        var statusListSizeLimit = statusListProperties.getStatusListSizeLimit();
        var config = statusListCreateDto.getConfig();

        if (isNull(config) || isNull(config.getBits())) {
            setMessageForValidation(constraintValidatorContext, "Status list size cannot be evaluated due to missing infos in config");
            return false;
        }

        int calculatedListSize = statusListCreateDto.getMaxLength() * config.getBits();

        if (calculatedListSize > statusListSizeLimit) {
            setMessageForValidation(constraintValidatorContext, "Status list has invalid size %s cannot exceed the maximum size limit of %s".formatted(calculatedListSize, statusListSizeLimit));
            return false;
        }

        return true;
    }

    private void setMessageForValidation(ConstraintValidatorContext constraintValidatorContext, String message) {
        constraintValidatorContext.disableDefaultConstraintViolation();
        constraintValidatorContext.buildConstraintViolationWithTemplate(message).addConstraintViolation();
    }
}