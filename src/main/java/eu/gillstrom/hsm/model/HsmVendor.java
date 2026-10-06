package eu.gillstrom.hsm.model;

public enum HsmVendor {
    YUBICO("Yubico", "YubiHSM 2"),
    SECUROSYS("Securosys", "Primus HSM"),
    AZURE("Microsoft", "Azure Key Vault HSM"),
    GOOGLE("Google Cloud", "Cloud HSM"),
    MARVELL("Marvell", "LiquidSecurity HSM"),
    THALES("Thales", "Luna HSM"),
    CRYPTO4A("Crypto4A", "QASM");
    
    private final String vendorName;
    private final String productName;
    
    HsmVendor(String vendorName, String productName) {
        this.vendorName = vendorName;
        this.productName = productName;
    }
    
    public String getVendorName() { return vendorName; }
    public String getProductName() { return productName; }
}
