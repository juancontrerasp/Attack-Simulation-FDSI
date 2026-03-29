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
import model.AttackResult;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class AttackEngine {

    public static void main(String[] args) {

        String target = "http://localhost:8080";

        System.out.println("=== ATTACK REPORT ===\n");

        List<SystemResult> results = new ArrayList<>();
        
        results.add(runAll("Target System", target));

        saveResultsToJson(results);
    }

    private static SystemResult runAll(String label, String baseUrl) {

        System.out.println(">> Testing: " + label + "\n");

        List<AttackResult> attacks = new ArrayList<>();
        
        // Authentication & Session Attacks
        AttackResult sql = SqlInjectionAttack.run(baseUrl);
        System.out.println(sql);
        attacks.add(sql);
        
        AttackResult brute = BruteForceAttack.run(baseUrl);
        System.out.println(brute);
        attacks.add(brute);
        
        AttackResult session = SessionFixationAttack.run(baseUrl);
        System.out.println(session);
        attacks.add(session);
        
        AttackResult jwt = JwtTokenAttack.run(baseUrl);
        System.out.println(jwt);
        attacks.add(jwt);
        
        // Input Validation Attacks
        AttackResult xss = XssAttack.run(baseUrl);
        System.out.println(xss);
        attacks.add(xss);
        
        AttackResult pathTraversal = PathTraversalAttack.run(baseUrl);
        System.out.println(pathTraversal);
        attacks.add(pathTraversal);
        
        // Configuration & Policy Attacks
        AttackResult leak = InfoLeakAttack.run(baseUrl);
        System.out.println(leak);
        attacks.add(leak);
        
        AttackResult headers = InsecureHeadersAttack.run(baseUrl);
        System.out.println(headers);
        attacks.add(headers);
        
        AttackResult cors = CorsAttack.run(baseUrl);
        System.out.println(cors);
        attacks.add(cors);
        
        AttackResult weakPass = WeakPasswordAttack.run(baseUrl);
        System.out.println(weakPass);
        attacks.add(weakPass);

        return new SystemResult(label, baseUrl, attacks);
    }

    private static void saveResultsToJson(List<SystemResult> results) {
        try (FileWriter writer = new FileWriter("results.json")) {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"timestamp\": \"").append(
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            ).append("\",\n");
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

    private static class SystemResult {
        String name;
        String url;
        List<AttackResult> attacks;

        SystemResult(String name, String url, List<AttackResult> attacks) {
            this.name = name;
            this.url = url;
            this.attacks = attacks;
        }
    }
}
