package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class XssAttack {

    public static AttackResult run(AttackConfig config) {

        String loginEndpoint    = config.loginEndpoint;
        String registerEndpoint = config.registerEndpoint;
        String loginUrl    = config.targetUrl + loginEndpoint;
        String registerUrl = config.targetUrl + registerEndpoint;

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
            String payload = String.format("""
            {
              "username": "%s",
              "password": "test123"
            }
            """, xss.replace("\"", "\\\""));

            String response = HttpUtil.post(loginUrl, payload);

            if (response.contains(xss) ||
                (response.contains("<script>") && !response.contains("&lt;script&gt;")) ||
                (response.contains("<img") && !response.contains("&lt;img"))) {

                String details = String.format(
                    "XSS vulnerability detected. Payload '%s' reflected in response without proper encoding",
                    truncate(xss, 50));

                return new AttackResult("Cross-Site Scripting (XSS)", true, details,
                    StrideCategory.TAMPERING, "XssAttack", loginEndpoint);
            }
        }

        // Test registration endpoint
        String regPayload = String.format("""
        {
          "username": "%s",
          "email": "test@test.com",
          "password": "Test123!"
        }
        """, xssPayloads[0].replace("\"", "\\\""));

        String regResponse = HttpUtil.post(registerUrl, regPayload);

        if (regResponse.contains(xssPayloads[0]) && !regResponse.contains("&lt;")) {
            return new AttackResult("Cross-Site Scripting (XSS)", true,
                "XSS vulnerability in registration endpoint. User input not sanitized",
                StrideCategory.TAMPERING, "XssAttack", registerEndpoint);
        }

        return new AttackResult("Cross-Site Scripting (XSS)", false,
            "No XSS vulnerability detected. Tested " + xssPayloads.length
            + " payloads. Input appears to be properly encoded",
            StrideCategory.TAMPERING, "XssAttack", loginEndpoint);
    }

    private static String truncate(String str, int maxLength) {
        return str.length() <= maxLength ? str : str.substring(0, maxLength) + "...";
    }
}
