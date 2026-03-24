package attacks;

import model.AttackResult;
import util.HttpUtil;

public class InfoLeakAttack {

    public static AttackResult run(String baseUrl) {

        String[] testUsers = {"nonexistent_user", "test_invalid_123", "unknown_account"};
        String[] knownUsers = {"admin", "root", "user"};

        String invalidUserResponse = null;
        String validUserResponse = null;

        for (String user : testUsers) {
            String payload = String.format("""
            {
              "username": "%s",
              "password": "wrongpassword123"
            }
            """, user);

            String response = HttpUtil.post(baseUrl + "/login", payload);
            if (invalidUserResponse == null) {
                invalidUserResponse = response;
            }
        }

        for (String user : knownUsers) {
            String payload = String.format("""
            {
              "username": "%s",
              "password": "wrongpassword123"
            }
            """, user);

            String response = HttpUtil.post(baseUrl + "/login", payload);
            if (!response.equals(invalidUserResponse)) {
                validUserResponse = response;
                
                String details = String.format(
                    "Information leakage detected. Different responses allow user enumeration. " +
                    "Invalid user response differs from valid user response. " +
                    "This reveals which usernames exist in the system.");
                    
                return new AttackResult("Information Leakage", true, details);
            }
        }

        return new AttackResult("Information Leakage", false,
                "No information leakage. Responses are consistent for both valid and invalid usernames");
    }
}