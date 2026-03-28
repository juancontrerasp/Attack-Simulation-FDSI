package model;

public class AttackResult {

    String name;
    boolean vulnerable;
    String details;

    public AttackResult(String name, boolean vulnerable, String details) {
        this.name = name;
        this.vulnerable = vulnerable;
        this.details = details;
    }

    public String getName() {
        return name;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public String getDetails() {
        return details;
    }

    public String toString() {
        return name + " → " +
                (vulnerable ? " VULNERABLE" : " SECURE") +
                "\nDetails: " + details + "\n";
    }

    public String toJson() {
        return String.format(
            "{\"name\":\"%s\",\"vulnerable\":%b,\"details\":\"%s\"}",
            escapeJson(name),
            vulnerable,
            escapeJson(details)
        );
    }

    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}