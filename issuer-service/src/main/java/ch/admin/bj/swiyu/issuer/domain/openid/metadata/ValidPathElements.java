package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PathElementsValidator.class)
@Documented
public @interface ValidPathElements {
    String message() default "path must only contain strings, nulls, or non-negative integers";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}