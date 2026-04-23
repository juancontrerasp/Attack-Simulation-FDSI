package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class InfoLeakAttack {

    public static AttackResult run(AttackConfig config) {

        String endpoint = config.loginEndpoint;
        String url = config.targetUrl + endpoint;

        String[] testUsers  = {"nonexistent_user", "test_invalid_123", "unknown_account"};
        String[] knownUsers = {"admin", "root", "user"};

        String invalidUserResponse = null;

        for (String user : testUsers) {
            String payload = String.format("""
            {
              "username": "%s",
              "password": "wrongpassword123"
            }
            """, user);

            String response = HttpUtil.post(url, payload);
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

            String response = HttpUtil.post(url, payload);

            if (!response.equals(invalidUserResponse)) {
                return new AttackResult("Information Leakage", true,
                    "Information leakage detected. Different responses allow user enumeration. "
                    + "Invalid user response differs from valid user response. "
                    + "This reveals which usernames exist in the system.",
                    StrideCategory.INFORMATION_DISCLOSURE, "InfoLeakAttack", endpoint);
            }
        }

        return new AttackResult("Information Leakage", false,
            "No information leakage. Responses are consistent for both valid and invalid usernames",
            StrideCategory.INFORMATION_DISCLOSURE, "InfoLeakAttack", endpoint);
    }
}
