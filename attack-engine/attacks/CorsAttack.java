package attacks;

import model.AttackResult;
import util.HttpUtil;

public class CorsAttack {

    public static AttackResult run(String baseUrl) {

        // Test CORS configuration with a suspicious origin
        String maliciousOrigin = "https://evil-site.com";
        
        String response = HttpUtil.getWithOrigin(baseUrl + "/api/auth/me", maliciousOrigin);

        // Check if CORS allows any origin
        if (response.contains("Access-Control-Allow-Origin: *")) {
            return new AttackResult("CORS Misconfiguration", true, 
                "Critical CORS vulnerability. Server allows requests from ANY origin (*). This enables cross-site attacks and data theft");
        }

        // Check if server reflects the origin without validation
        if (response.contains("Access-Control-Allow-Origin: " + maliciousOrigin)) {
            return new AttackResult("CORS Misconfiguration", true, 
                "CORS vulnerability. Server reflects arbitrary origins without validation. Attacker-controlled sites can access authenticated endpoints");
        }

        // Check if credentials are allowed with wildcard origin
        if (response.contains("Access-Control-Allow-Origin: *") && 
            response.contains("Access-Control-Allow-Credentials: true")) {
            return new AttackResult("CORS Misconfiguration", true, 
                "Critical CORS misconfiguration. Allows credentials with wildcard origin. This is invalid and extremely dangerous");
        }

        // Test with null origin (common bypass attempt)
        response = HttpUtil.getWithOrigin(baseUrl + "/api/auth/me", "null");
        
        if (response.contains("Access-Control-Allow-Origin: null")) {
            return new AttackResult("CORS Misconfiguration", true, 
                "CORS vulnerability. Server allows 'null' origin. This can be exploited via sandboxed iframes and file:// URLs");
        }

        return new AttackResult("CORS Misconfiguration", false, 
            "CORS policy properly configured. Rejects unauthorized origins and doesn't use wildcard with credentials");
    }
}
