package ch.admin.bj.swiyu.issuer.test;

import java.util.ArrayList;
import java.util.List;

/**
 * This class intentionally contains PMD violations to test the CI/CD pipeline.
 * It should trigger PMD errors during pull request checks.
 */
public class PmdTestViolations {
    
    // PMD Violation: Unused private field
    private String unusedField = "unused";
    
    // PMD Violation: Empty method
    public void emptyMethod() {
    }
    
    // PMD Violation: Method with too many parameters
    public void methodWithTooManyParameters(String param1, String param2, String param3, 
                                          String param4, String param5, String param6,
                                          String param7, String param8, String param9,
                                          String param10, String param11) {
        // Do nothing
    }

}
