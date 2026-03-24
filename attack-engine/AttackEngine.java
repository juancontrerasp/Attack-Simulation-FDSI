import attacks.BruteForceAttack;
import attacks.InfoLeakAttack;
import attacks.SqlInjectionAttack;

public class AttackEngine {

    public static void main(String[] args) {

        String secure = "http://localhost:8080/secure";
        String vulnerable = "http://localhost:8080/vulnerable";

        System.out.println("=== ATTACK REPORT ===\n");

        runAll("SECURE SYSTEM", secure);
        runAll("VULNERABLE SYSTEM", vulnerable);
    }

    private static void runAll(String label, String baseUrl) {

        System.out.println(">> Testing: " + label + "\n");

        System.out.println(SqlInjectionAttack.run(baseUrl));
        System.out.println(BruteForceAttack.run(baseUrl));
        System.out.println(InfoLeakAttack.run(baseUrl));
    }
}
