package ch.admin.bj.swiyu.issuer.dto.statuslist;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ValidStatusListMaxLengthValidator.class)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidStatusListMaxLength {

    String message() default "Invalid maxLength for status list";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}