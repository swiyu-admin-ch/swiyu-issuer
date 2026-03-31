package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = MetadataLogoUriValidator.class)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidMetadataLogoUri {
    String message() default "must be a valid URI or a base64 data image (data:image/png;base64 or data:image/jpeg;base64)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}