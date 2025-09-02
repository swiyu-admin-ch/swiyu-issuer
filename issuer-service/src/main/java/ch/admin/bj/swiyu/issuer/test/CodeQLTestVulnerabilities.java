package ch.admin.bj.swiyu.issuer.test;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;


/**
 * This class intentionally contains security vulnerabilities to test CodeQL detection.
 * It should trigger CodeQL security alerts during pull request checks.
 */
@Slf4j
public class CodeQLTestVulnerabilities {

    
    // CodeQL Violation: SQL Injection vulnerability
    public void sqlInjectionVulnerability(Connection conn, String userInput) throws SQLException {
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); // Vulnerable to SQL injection
    }
    
    // CodeQL Violation: Path traversal vulnerability
    public File pathTraversalVulnerability(String fileName) {
        return new File("/safe/directory/" + fileName); // Vulnerable to path traversal
    }
    
    // CodeQL Violation: Command injection
    public void commandInjectionVulnerability(String userInput) throws IOException {
        Runtime.getRuntime().exec("ls " + userInput); // Vulnerable to command injection
    }
    
    // CodeQL Violation: Hardcoded credentials
    public void hardcodedCredentials() {
        String password = "admin123"; // Hardcoded password
        String apiKey = "sk-1234567890abcdef"; // Hardcoded API key
        log.info("Using password: " + password);
    }
    
    // CodeQL Violation: Information disclosure through logging
    public void sensitiveDataLogging(String creditCardNumber, String ssn) {
        log.info("Processing credit card: " + creditCardNumber);
        log.info("SSN: " + ssn);
    }
    
    // CodeQL Violation: Unsafe deserialization
    public Object unsafeDeserialization(InputStream input) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject(); // Unsafe deserialization
    }
    
    // CodeQL Violation: Weak cryptography
    public void weakCryptography() throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5"); // Weak hash
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES"); // Weak encryption
    }
    
    // CodeQL Violation: Resource leak
    public void resourceLeak(String fileName) throws IOException {
        FileInputStream fis = new FileInputStream(fileName);
        // File stream not closed - resource leak
        fis.read();
    }
    
    // CodeQL Violation: Null pointer dereference
    public void nullPointerDereference(String input) {
        String result = null;
        if (input.equals("test")) {
            result = "valid";
        }
        System.out.println(result.length()); // Potential null pointer dereference
    }
    
    // CodeQL Violation: Unsafe reflection
    public void unsafeReflection(String className) throws Exception {
        Class<?> clazz = Class.forName(className); // Unsafe reflection with user input
        Object instance = clazz.getDeclaredConstructor().newInstance();
    }
}
