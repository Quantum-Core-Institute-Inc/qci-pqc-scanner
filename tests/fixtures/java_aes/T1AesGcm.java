import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Tier 1: authenticated encryption, literal parameters. */
public class T1AesGcm {
    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();

        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        gcm.updateAAD("header-v2".getBytes());
        System.out.println(gcm.doFinal("customer-record".getBytes()).length);
    }
}
