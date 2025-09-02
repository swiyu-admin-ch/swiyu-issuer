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
    
    // PMD Violation: Unused local variable
    public void methodWithUnusedVariable() {
        String unusedVariable = "I am not used";
        System.out.println("Hello World");
    }
    
    // PMD Violation: Assignment in operand (should be ==)
    public boolean assignmentInOperand(String input) {
        String value = null;
        if ((value = input) != null) {
            return true;
        }
        return false;
    }
    
    // PMD Violation: Inefficient use of StringBuffer
    public String inefficientStringBuffer() {
        StringBuffer buffer = new StringBuffer();
        buffer.append("Hello");
        buffer.append(" ");
        buffer.append("World");
        return buffer.toString();
    }
    
    // PMD Violation: Avoid instantiating Boolean objects
    public Boolean booleanInstantiation() {
        return new Boolean(true);
    }
    
    // PMD Violation: Use ArrayList instead of Vector
    public List<String> useVector() {
        return new java.util.Vector<>();
    }
    
    // PMD Violation: Avoid printStackTrace
    public void catchException() {
        try {
            // Some risky operation
            throw new RuntimeException("Test exception");
        } catch (Exception e) {
            e.printStackTrace(); // This should trigger PMD violation
        }
    }
    
    // PMD Violation: Local variable could be final
    public void localVariableCouldBeFinal() {
        String message = "Hello World"; // Should be final
        System.out.println(message);
    }
    
    // PMD Violation: Avoid using implementation types like ArrayList
    public ArrayList<String> returnImplementationType() {
        return new ArrayList<>();
    }
}
