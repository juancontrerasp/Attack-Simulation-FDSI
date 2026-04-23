package model;

public class AttackResult {

    private final String name;
    private final boolean vulnerable;
    private final String details;
    private final StrideCategory strideCategory;
    private final String attackClass;
    private final String endpointTested;

    public AttackResult(String name, boolean vulnerable, String details,
                        StrideCategory strideCategory, String attackClass, String endpointTested) {
        this.name           = name;
        this.vulnerable     = vulnerable;
        this.details        = details;
        this.strideCategory = strideCategory;
        this.attackClass    = attackClass;
        this.endpointTested = endpointTested;
    }

    public String getName()               { return name; }
    public boolean isVulnerable()         { return vulnerable; }
    public String getDetails()            { return details; }
    public StrideCategory getStride()     { return strideCategory; }
    public String getAttackClass()        { return attackClass; }
    public String getEndpointTested()     { return endpointTested; }

    @Override
    public String toString() {
        return name + " [" + (strideCategory != null ? strideCategory.toJsonValue() : "?") + "]"
            + " → " + (vulnerable ? "VULNERABLE" : "SECURE")
            + "\nDetails: " + details + "\n";
    }

    public String toJson() {
        return String.format(
            "{\"name\":\"%s\",\"vulnerable\":%b,\"stride_category\":\"%s\","
            + "\"attack_class\":\"%s\",\"endpoint_tested\":\"%s\",\"details\":\"%s\"}",
            esc(name),
            vulnerable,
            strideCategory != null ? strideCategory.toJsonValue() : "",
            esc(attackClass  != null ? attackClass  : ""),
            esc(endpointTested != null ? endpointTested : ""),
            esc(details)
        );
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
