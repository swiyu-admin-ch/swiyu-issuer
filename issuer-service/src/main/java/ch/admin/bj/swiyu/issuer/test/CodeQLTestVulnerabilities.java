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

}
