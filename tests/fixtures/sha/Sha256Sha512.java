import java.security.MessageDigest;
public class Sha256Sha512 {
    public static void main(String[] args) throws Exception {
        MessageDigest.getInstance("SHA-256").digest("a".getBytes());
        MessageDigest.getInstance("SHA256").digest("a".getBytes());
        MessageDigest.getInstance("SHA-512").digest("a".getBytes());
        MessageDigest.getInstance("SHA512").digest("a".getBytes());
    }
}
