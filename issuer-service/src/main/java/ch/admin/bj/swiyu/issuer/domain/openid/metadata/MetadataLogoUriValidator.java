package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class MetadataLogoUriValidator implements ConstraintValidator<ValidMetadataLogoUri, String> {

    private static final String PNG_PREFIX = "data:image/png;base64";
    private static final String JPEG_PREFIX = "data:image/jpeg;base64";

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {

        // This check only checks the validity of the URI, but not if the URI is not null. This must be handled with @NotNull on the field.
        if (value == null) {
            return true;
        }

        return value.startsWith(PNG_PREFIX) || value.startsWith(JPEG_PREFIX);
    }
}