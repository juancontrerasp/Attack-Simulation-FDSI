package attacks;

import model.AttackResult;
import util.HttpUtil;

public class BruteForceAttack {

    public static AttackResult run(String baseUrl) {

        int attempts = 20;
        int successCount = 0;

        for (int i = 0; i < attempts; i++) {

            String payload = """
            {
              "username": "admin",
              "password": "wrongpass"
            }
            """;

            String response = HttpUtil.post(baseUrl + "/login", payload);

            if (!response.contains("blocked") && !response.contains("too many")) {
                successCount++;
            }
        }

        boolean vulnerable = successCount == attempts;

        return new AttackResult("Brute Force", vulnerable,
                "Attempts allowed: " + successCount + "/" + attempts);
    }
}
