package attacks;

import model.AttackResult;
import util.HttpUtil;

public class WeakPasswordAttack {

    public static AttackResult run(String baseUrl) {

        // Test if registration allows weak passwords
        String[] weakPasswords = {
            "123456",
            "password",
            "12345678",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "test"
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

            String response = HttpUtil.post(baseUrl + "/register", payload);

            // Check if weak password was accepted
            if (response.contains("success") || response.contains("created") || 
                response.contains("registered") || (response.contains("201") && !response.contains("error"))) {
                accepted++;
                if (acceptedPassword == null) {
                    acceptedPassword = weakPass;
                }
            }
        }

        boolean vulnerable = accepted > 0;
        
        String details;
        if (vulnerable) {
            details = String.format("Weak password policy detected. %d/%d weak passwords accepted (e.g., '%s'). Password complexity requirements missing or insufficient", 
                accepted, weakPasswords.length, acceptedPassword);
        } else {
            details = String.format("Strong password policy enforced. All %d weak passwords rejected. System requires complex passwords", 
                weakPasswords.length);
        }

        return new AttackResult("Weak Password Policy", vulnerable, details);
    }
}
