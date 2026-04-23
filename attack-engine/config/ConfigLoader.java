package config;

import org.yaml.snakeyaml.Yaml;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ConfigLoader {

    private static final Set<String> KNOWN_FIELDS = new HashSet<>(Arrays.asList(
        "target_url", "endpoints", "timeout_ms", "max_passwords",
        "passwords_file", "enabled_attacks"
    ));

    @SuppressWarnings("unchecked")
    public static AttackConfig load(String path) {
        File file = new File(path);
        if (!file.exists()) {
            System.err.println("Warning: archivo de configuracion no encontrado: " + path
                + ". Usando valores por defecto.");
            return AttackConfig.defaults();
        }

        Yaml yaml = new Yaml();
        Map<String, Object> raw;
        try (InputStream in = new FileInputStream(file)) {
            raw = yaml.load(in);
        } catch (Exception e) {
            throw new ConfigException(
                "Error de configuracion: no se pudo parsear el YAML '" + path + "': " + e.getMessage());
        }

        if (raw == null) raw = new HashMap<>();

        // Warn on unknown fields (don't fail — allows forward compat)
        for (String key : raw.keySet()) {
            if (!KNOWN_FIELDS.contains(key)) {
                System.err.println("Warning: campo desconocido en configuracion: '" + key + "'");
            }
        }

        AttackConfig cfg = new AttackConfig();

        // target_url (required)
        if (!raw.containsKey("target_url")) {
            throw new ConfigException("Error de configuracion: target_url es requerido");
        }
        String targetUrl = asString(raw.get("target_url"), "target_url");
        if (!isValidHttpUrl(targetUrl)) {
            throw new ConfigException(
                "Error de configuracion: target_url debe ser una URL HTTP/HTTPS valida");
        }
        cfg.targetUrl = targetUrl;

        // endpoints (optional)
        Map<String, Object> endpoints = new HashMap<>();
        if (raw.containsKey("endpoints") && raw.get("endpoints") instanceof Map) {
            endpoints = (Map<String, Object>) raw.get("endpoints");
        }
        cfg.loginEndpoint   = asStringOr(endpoints.get("login"),    "/login");
        cfg.registerEndpoint = asStringOr(endpoints.get("register"), "/register");
        cfg.authMeEndpoint  = asStringOr(endpoints.get("auth_me"),  "/api/auth/me");

        // timeout_ms (optional, default 5000, must be positive)
        int timeout = toInt(raw.getOrDefault("timeout_ms", 5000), "timeout_ms");
        if (timeout <= 0) {
            throw new ConfigException(
                "Error de configuracion: timeout_ms debe ser un entero positivo");
        }
        cfg.timeoutMs = timeout;

        // max_passwords (optional, default 100, range 1-1000)
        int maxPwd = toInt(raw.getOrDefault("max_passwords", 100), "max_passwords");
        if (maxPwd < 1 || maxPwd > 1000) {
            throw new ConfigException(
                "Error de configuracion: max_passwords debe estar entre 1 y 1000");
        }
        cfg.maxPasswords = maxPwd;

        // passwords_file (optional)
        cfg.passwordsFile = asStringOr(raw.get("passwords_file"), "passwords.txt");

        // enabled_attacks (optional, default all)
        if (raw.containsKey("enabled_attacks") && raw.get("enabled_attacks") instanceof List) {
            List<String> requested = (List<String>) raw.get("enabled_attacks");
            for (String name : requested) {
                if (!AttackConfig.ALL_ATTACKS.contains(name)) {
                    System.err.println("Warning: nombre de ataque desconocido: '" + name + "'");
                }
            }
            cfg.enabledAttacks = requested;
        } else {
            cfg.enabledAttacks = AttackConfig.ALL_ATTACKS;
        }

        return cfg;
    }

    private static boolean isValidHttpUrl(String url) {
        if (url == null || url.isBlank()) return false;
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            return ("http".equals(scheme) || "https".equals(scheme)) && uri.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String asString(Object val, String field) {
        if (val instanceof String) return (String) val;
        throw new ConfigException(
            "Error de configuracion: " + field + " debe ser una cadena de texto");
    }

    private static String asStringOr(Object val, String fallback) {
        if (val instanceof String) return (String) val;
        return fallback;
    }

    private static int toInt(Object val, String field) {
        if (val instanceof Integer) return (Integer) val;
        if (val instanceof Long)    return ((Long) val).intValue();
        if (val instanceof String) {
            try { return Integer.parseInt((String) val); } catch (NumberFormatException ignored) { }
        }
        throw new ConfigException(
            "Error de configuracion: " + field + " debe ser un numero entero");
    }
}
