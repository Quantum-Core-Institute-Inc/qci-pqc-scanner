public class MoreCases {
    private static final String ALG = "DESede";
    private static final String MODE = "CBC";
    enum HashPolicy { LEGACY("SHA-1"); }
    static void run() throws Exception {
        javax.crypto.Cipher.getInstance(ALG + "/" + MODE + "/PKCS5Padding");
        java.security.MessageDigest.getInstance(HashPolicy.LEGACY.jcaName);
    }
}
