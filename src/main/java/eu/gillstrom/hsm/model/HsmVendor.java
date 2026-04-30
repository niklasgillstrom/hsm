package eu.gillstrom.hsm.model;

public enum HsmVendor {
    YUBICO("Yubico", "YubiHSM 2"),
    SECUROSYS("Securosys", "Primus HSM"),
    AZURE("Microsoft", "Azure Key Vault HSM"),
    GOOGLE("Google Cloud", "Cloud HSM");
    
    private final String vendorName;
    private final String productName;
    
    HsmVendor(String vendorName, String productName) {
        this.vendorName = vendorName;
        this.productName = productName;
    }
    
    public String getVendorName() { return vendorName; }
    public String getProductName() { return productName; }
}
