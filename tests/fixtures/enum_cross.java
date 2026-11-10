public class EnumCross {
    enum HashPolicy { LEGACY("SHA-1"); }
    static void run() throws Exception {
        java.security.MessageDigest.getInstance(HashPolicy.LEGACY.jcaName);
    }
}
