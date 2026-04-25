package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class CorsAttack {

    public static AttackResult run(AttackConfig config) {

        String endpoint = config.authMeEndpoint;
        String url = config.targetUrl + endpoint;

        String maliciousOrigin = "https://evil-site.com";
        String response = HttpUtil.getWithOrigin(url, maliciousOrigin);

        if (response.contains("Access-Control-Allow-Origin: *")) {
            return new AttackResult("CORS Misconfiguration", true,
                "Critical CORS vulnerability. Server allows requests from ANY origin (*). "
                + "This enables cross-site attacks and data theft",
                StrideCategory.SPOOFING, "CorsAttack", endpoint);
        }

        if (response.contains("Access-Control-Allow-Origin: " + maliciousOrigin)) {
            return new AttackResult("CORS Misconfiguration", true,
                "CORS vulnerability. Server reflects arbitrary origins without validation. "
                + "Attacker-controlled sites can access authenticated endpoints",
                StrideCategory.SPOOFING, "CorsAttack", endpoint);
        }

        if (response.contains("Access-Control-Allow-Origin: *") &&
            response.contains("Access-Control-Allow-Credentials: true")) {
            return new AttackResult("CORS Misconfiguration", true,
                "Critical CORS misconfiguration. Allows credentials with wildcard origin. "
                + "This is invalid and extremely dangerous",
                StrideCategory.SPOOFING, "CorsAttack", endpoint);
        }

        // Test null origin bypass
        response = HttpUtil.getWithOrigin(url, "null");

        if (response.contains("Access-Control-Allow-Origin: null")) {
            return new AttackResult("CORS Misconfiguration", true,
                "CORS vulnerability. Server allows 'null' origin. "
                + "This can be exploited via sandboxed iframes and file:// URLs",
                StrideCategory.SPOOFING, "CorsAttack", endpoint);
        }

        return new AttackResult("CORS Misconfiguration", false,
            "CORS policy properly configured. Rejects unauthorized origins "
            + "and doesn't use wildcard with credentials",
            StrideCategory.SPOOFING, "CorsAttack", endpoint);
    }
}
