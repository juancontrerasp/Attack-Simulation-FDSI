package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class InsecureHeadersAttack {

    public static AttackResult run(AttackConfig config) {

        String endpoint = "/";
        String response = HttpUtil.get(config.targetUrl + endpoint);

        boolean hasXFrameOptions            = response.toLowerCase().contains("x-frame-options");
        boolean hasXContentTypeOptions      = response.toLowerCase().contains("x-content-type-options");
        boolean hasStrictTransportSecurity  = response.toLowerCase().contains("strict-transport-security");
        boolean hasContentSecurityPolicy    = response.toLowerCase().contains("content-security-policy");
        boolean hasXXssProtection           = response.toLowerCase().contains("x-xss-protection");

        int missingHeaders = 0;
        StringBuilder missing = new StringBuilder();

        if (!hasXFrameOptions)           { missingHeaders++; missing.append("X-Frame-Options, "); }
        if (!hasXContentTypeOptions)     { missingHeaders++; missing.append("X-Content-Type-Options, "); }
        if (!hasStrictTransportSecurity) { missingHeaders++; missing.append("Strict-Transport-Security, "); }
        if (!hasContentSecurityPolicy)   { missingHeaders++; missing.append("Content-Security-Policy, "); }
        if (!hasXXssProtection)          { missingHeaders++; missing.append("X-XSS-Protection, "); }

        boolean vulnerable = missingHeaders > 0;

        String details;
        if (vulnerable) {
            String missingList = missing.toString().replaceAll(", $", "");
            details = String.format("Missing %d security headers: %s. "
                + "This increases risk of clickjacking, XSS, and other attacks",
                missingHeaders, missingList);
        } else {
            details = "All essential security headers present "
                + "(X-Frame-Options, X-Content-Type-Options, HSTS, CSP, X-XSS-Protection)";
        }

        return new AttackResult("Insecure HTTP Headers", vulnerable, details,
            StrideCategory.INFORMATION_DISCLOSURE, "InsecureHeadersAttack", endpoint);
    }
}
