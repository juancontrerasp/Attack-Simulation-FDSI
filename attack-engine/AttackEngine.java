import attacks.BruteForceAttack;
import attacks.CorsAttack;
import attacks.InfoLeakAttack;
import attacks.InsecureHeadersAttack;
import attacks.JwtTokenAttack;
import attacks.PathTraversalAttack;
import attacks.SessionFixationAttack;
import attacks.SqlInjectionAttack;
import attacks.WeakPasswordAttack;
import attacks.XssAttack;
import config.AttackConfig;
import config.ConfigException;
import config.ConfigLoader;
import model.AttackResult;
import util.HttpUtil;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AttackEngine {

    public static void main(String[] args) {
        // ── Parse CLI arguments ──────────────────────────────────────────────
        String configPath    = "config/attack-config.yaml";
        String targetOverride = null;
        List<String> attacksFilter = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config":
                    if (i + 1 < args.length) configPath = args[++i];
                    break;
                case "--target":
                    if (i + 1 < args.length) targetOverride = args[++i];
                    break;
                case "--attacks":
                    if (i + 1 < args.length)
                        attacksFilter = Arrays.asList(args[++i].split(","));
                    break;
            }
        }

        // ── Load config ──────────────────────────────────────────────────────
        AttackConfig config;
        try {
            config = ConfigLoader.load(configPath);
        } catch (ConfigException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }

        // CLI overrides
        if (targetOverride != null) {
            config.targetUrl = targetOverride;
        }
        if (attacksFilter != null) {
            config.enabledAttacks = attacksFilter;
        }

        // ── Configure HTTP client with timeout from config ───────────────────
        HttpUtil.configure(config.timeoutMs, config.timeoutMs);

        System.out.println("=== ATTACK REPORT ===\n");
        System.out.println("Target: " + config.targetUrl);
        System.out.println("Config: " + configPath);
        System.out.println("Attacks enabled: " + config.enabledAttacks.size() + "\n");

        List<SystemResult> results = new ArrayList<>();
        results.add(runAll("Target System", config));

        saveResultsToJson(results, config);
    }

    private static SystemResult runAll(String label, AttackConfig config) {
        System.out.println(">> Testing: " + label + " (" + config.targetUrl + ")\n");

        List<AttackResult> attacks = new ArrayList<>();

        run(attacks, config, "SqlInjection",    () -> SqlInjectionAttack.run(config));
        run(attacks, config, "BruteForce",      () -> BruteForceAttack.run(config));
        run(attacks, config, "SessionFixation", () -> SessionFixationAttack.run(config));
        run(attacks, config, "JwtToken",        () -> JwtTokenAttack.run(config));
        run(attacks, config, "XSS",             () -> XssAttack.run(config));
        run(attacks, config, "PathTraversal",   () -> PathTraversalAttack.run(config));
        run(attacks, config, "InfoLeak",        () -> InfoLeakAttack.run(config));
        run(attacks, config, "InsecureHeaders", () -> InsecureHeadersAttack.run(config));
        run(attacks, config, "CORS",            () -> CorsAttack.run(config));
        run(attacks, config, "WeakPassword",    () -> WeakPasswordAttack.run(config));

        return new SystemResult(label, config.targetUrl, attacks);
    }

    @FunctionalInterface
    private interface AttackRunner {
        AttackResult execute();
    }

    private static void run(List<AttackResult> results, AttackConfig config,
                             String name, AttackRunner runner) {
        if (!config.isEnabled(name)) return;
        AttackResult result = runner.execute();
        System.out.println(result);
        results.add(result);
    }

    private static void saveResultsToJson(List<SystemResult> results, AttackConfig config) {
        try (FileWriter writer = new FileWriter("results.json")) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"timestamp\": \"").append(
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            ).append("\",\n");
            json.append("  \"config_file\": \"").append(escJson(config.targetUrl)).append("\",\n");
            json.append("  \"systems\": [\n");

            for (int i = 0; i < results.size(); i++) {
                SystemResult system = results.get(i);
                json.append("    {\n");
                json.append("      \"name\": \"").append(system.name).append("\",\n");
                json.append("      \"url\": \"").append(system.url).append("\",\n");
                json.append("      \"attacks\": [\n");

                for (int j = 0; j < system.attacks.size(); j++) {
                    json.append("        ").append(system.attacks.get(j).toJson());
                    if (j < system.attacks.size() - 1) json.append(",");
                    json.append("\n");
                }

                json.append("      ]\n");
                json.append("    }");
                if (i < results.size() - 1) json.append(",");
                json.append("\n");
            }

            json.append("  ]\n");
            json.append("}\n");

            writer.write(json.toString());
            System.out.println("\n✓ Results saved to results.json");

        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
        }
    }

    private static String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static class SystemResult {
        final String name;
        final String url;
        final List<AttackResult> attacks;

        SystemResult(String name, String url, List<AttackResult> attacks) {
            this.name    = name;
            this.url     = url;
            this.attacks = attacks;
        }
    }
}
