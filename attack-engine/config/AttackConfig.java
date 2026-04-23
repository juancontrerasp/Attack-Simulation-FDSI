package config;

import java.util.Arrays;
import java.util.List;

public class AttackConfig {

    public static final List<String> ALL_ATTACKS = Arrays.asList(
        "SqlInjection", "BruteForce", "SessionFixation", "JwtToken",
        "XSS", "PathTraversal", "InfoLeak", "InsecureHeaders", "CORS", "WeakPassword"
    );

    public String targetUrl;
    public String loginEndpoint;
    public String registerEndpoint;
    public String authMeEndpoint;
    public int timeoutMs;
    public int maxPasswords;
    public String passwordsFile;
    public List<String> enabledAttacks;

    public boolean isEnabled(String attackName) {
        if (enabledAttacks == null) return true;
        return enabledAttacks.contains(attackName);
    }

    public static AttackConfig defaults() {
        AttackConfig cfg = new AttackConfig();
        cfg.targetUrl       = "http://localhost:8080";
        cfg.loginEndpoint   = "/login";
        cfg.registerEndpoint = "/register";
        cfg.authMeEndpoint  = "/api/auth/me";
        cfg.timeoutMs       = 5000;
        cfg.maxPasswords    = 100;
        cfg.passwordsFile   = "passwords.txt";
        cfg.enabledAttacks  = ALL_ATTACKS;
        return cfg;
    }
}
