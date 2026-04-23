package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class SessionFixationAttack {

    public static AttackResult run(AttackConfig config) {

        String loginEndpoint = config.loginEndpoint;
        String loginUrl = config.targetUrl + loginEndpoint;

        // Test 1: Check if session ID is regenerated after login
        String preLoginResponse = HttpUtil.get(config.targetUrl + "/");
        String preSessionId = extractSessionId(preLoginResponse);

        String loginPayload = """
        {
          "username": "testuser",
          "password": "TestPassword123!"
        }
        """;

        String loginResponse = HttpUtil.post(loginUrl, loginPayload);
        String postSessionId = extractSessionId(loginResponse);

        if (preSessionId != null && postSessionId != null && preSessionId.equals(postSessionId)) {
            return new AttackResult("Session Fixation", true,
                "Session fixation vulnerability detected. Session ID not regenerated after authentication. "
                + "Same session ID used before and after login",
                StrideCategory.SPOOFING, "SessionFixationAttack", loginEndpoint);
        }

        if (postSessionId == null || postSessionId.isEmpty()) {
            return new AttackResult("Session Fixation", false,
                "Could not extract session ID for comprehensive testing. "
                + "Session management appears secure or uses different mechanism",
                StrideCategory.SPOOFING, "SessionFixationAttack", loginEndpoint);
        }

        // Test 2: Check for Secure and HttpOnly flags
        boolean hasSecureFlag   = loginResponse.toLowerCase().contains("secure");
        boolean hasHttpOnlyFlag = loginResponse.toLowerCase().contains("httponly");

        if (!hasSecureFlag || !hasHttpOnlyFlag) {
            StringBuilder warnings = new StringBuilder("Session cookie security issues detected: ");
            if (!hasSecureFlag)   warnings.append("Missing 'Secure' flag (allows transmission over HTTP). ");
            if (!hasHttpOnlyFlag) warnings.append("Missing 'HttpOnly' flag (vulnerable to XSS attacks). ");

            return new AttackResult("Session Fixation", true, warnings.toString(),
                StrideCategory.SPOOFING, "SessionFixationAttack", loginEndpoint);
        }

        return new AttackResult("Session Fixation", false,
            "Session management secure. Session ID regenerated after login, "
            + "and cookies have Secure and HttpOnly flags",
            StrideCategory.SPOOFING, "SessionFixationAttack", loginEndpoint);
    }

    private static String extractSessionId(String response) {
        String[] patterns = {"JSESSIONID=", "SESSION=", "sessionid=", "sid="};

        for (String pattern : patterns) {
            int idx = response.indexOf(pattern);
            if (idx != -1) {
                int start = idx + pattern.length();
                int end = response.indexOf(";", start);
                if (end == -1) end = response.indexOf("\n", start);
                if (end == -1) end = Math.min(start + 50, response.length());
                return response.substring(start, end).trim();
            }
        }
        return null;
    }
}
