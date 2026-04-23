package model;

public enum StrideCategory {

    SPOOFING("Spoofing"),
    TAMPERING("Tampering"),
    REPUDIATION("Repudiation"),
    INFORMATION_DISCLOSURE("InformationDisclosure"),
    DENIAL_OF_SERVICE("DenialOfService"),
    ELEVATION_OF_PRIVILEGE("ElevationOfPrivilege");

    private final String jsonValue;

    StrideCategory(String jsonValue) {
        this.jsonValue = jsonValue;
    }

    public String toJsonValue() {
        return jsonValue;
    }
}
