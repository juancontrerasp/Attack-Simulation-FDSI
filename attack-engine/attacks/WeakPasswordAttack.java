package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class WeakPasswordAttack {

    public static AttackResult run(AttackConfig config) {

        String endpoint = config.registerEndpoint;
        String url = config.targetUrl + endpoint;

        String[] weakPasswords = {
            "123456", "password", "12345678", "qwerty",
            "abc123", "password123", "admin", "test"
        };

        int accepted = 0;
        String acceptedPassword = null;

        for (String weakPass : weakPasswords) {
            String payload = String.format("""
            {
              "username": "testuser_%d",
              "email": "test_%d@example.com",
              "password": "%s"
            }
            """, System.currentTimeMillis(), System.currentTimeMillis(), weakPass);

            String response = HttpUtil.post(url, payload);

            if (response.contains("success") || response.contains("created") ||
                response.contains("registered") ||
                (response.contains("201") && !response.contains("error"))) {
                accepted++;
                if (acceptedPassword == null) acceptedPassword = weakPass;
            }
        }

        boolean vulnerable = accepted > 0;

        String details;
        if (vulnerable) {
            details = String.format(
                "Weak password policy detected. %d/%d weak passwords accepted (e.g., '%s'). "
                + "Password complexity requirements missing or insufficient",
                accepted, weakPasswords.length, acceptedPassword);
        } else {
            details = String.format(
                "Strong password policy enforced. All %d weak passwords rejected. "
                + "System requires complex passwords",
                weakPasswords.length);
        }

        return new AttackResult("Weak Password Policy", vulnerable, details,
            StrideCategory.ELEVATION_OF_PRIVILEGE, "WeakPasswordAttack", endpoint);
    }
}
