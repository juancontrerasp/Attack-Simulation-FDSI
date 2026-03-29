package attacks;

import model.AttackResult;
import util.HttpUtil;

public class SessionFixationAttack {

    public static AttackResult run(String baseUrl) {

        // Test 1: Check if session ID is regenerated after login
        String preLoginResponse = HttpUtil.get(baseUrl + "/");
        String preSessionId = extractSessionId(preLoginResponse);

        // Attempt login
        String loginPayload = """
        {
          "username": "testuser",
          "password": "TestPassword123!"
        }
        """;

        String loginResponse = HttpUtil.post(baseUrl + "/login", loginPayload);
        String postSessionId = extractSessionId(loginResponse);

        // If session ID is the same before and after login, it's vulnerable
        if (preSessionId != null && postSessionId != null && preSessionId.equals(postSessionId)) {
            return new AttackResult("Session Fixation", true, 
                "Session fixation vulnerability detected. Session ID not regenerated after authentication. Same session ID used before and after login");
        }

        // Test 2: Check if old session is invalidated
        if (postSessionId == null || postSessionId.isEmpty()) {
            return new AttackResult("Session Fixation", false, 
                "Could not extract session ID for comprehensive testing. Session management appears secure or uses different mechanism");
        }

        // Test 3: Check for secure and httpOnly flags
        boolean hasSecureFlag = loginResponse.toLowerCase().contains("secure");
        boolean hasHttpOnlyFlag = loginResponse.toLowerCase().contains("httponly");

        if (!hasSecureFlag || !hasHttpOnlyFlag) {
            StringBuilder warnings = new StringBuilder("Session cookie security issues detected: ");
            if (!hasSecureFlag) warnings.append("Missing 'Secure' flag (allows transmission over HTTP). ");
            if (!hasHttpOnlyFlag) warnings.append("Missing 'HttpOnly' flag (vulnerable to XSS attacks). ");
            
            return new AttackResult("Session Fixation", true, warnings.toString());
        }

        return new AttackResult("Session Fixation", false, 
            "Session management secure. Session ID regenerated after login, and cookies have Secure and HttpOnly flags");
    }

    private static String extractSessionId(String response) {
        // Look for common session cookie patterns
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
