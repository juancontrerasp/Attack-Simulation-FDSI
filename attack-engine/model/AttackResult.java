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

    public String toString() {
        return name + " → " +
                (vulnerable ? " VULNERABLE" : " SECURE") +
                "\nDetails: " + details + "\n";
    }
}