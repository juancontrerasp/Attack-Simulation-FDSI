package attacks;

import model.AttackResult;
import util.HttpUtil;

public class InfoLeakAttack {

    public static AttackResult run(String baseUrl) {

        String payloadUserNotFound = """
        {
          "username": "nonexistent",
          "password": "1234"
        }
        """;

        String payloadWrongPassword = """
        {
          "username": "admin",
          "password": "wrong"
        }
        """;

        String res1 = HttpUtil.post(baseUrl + "/login", payloadUserNotFound);
        String res2 = HttpUtil.post(baseUrl + "/login", payloadWrongPassword);

        boolean vulnerable = !res1.equals(res2);

        return new AttackResult("Information Leakage", vulnerable,
                "Different responses detected");
    }
}