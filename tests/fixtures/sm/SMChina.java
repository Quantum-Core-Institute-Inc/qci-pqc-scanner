import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;

/** Chinese commercial algorithms via JCA providers. */
public class SMChina {
    public static void main(String[] args) throws Exception {
        Signature sm2 = Signature.getInstance("SM3withSM2");
        MessageDigest sm3 = MessageDigest.getInstance("SM3");
        Cipher sm4 = Cipher.getInstance("SM4/CBC/PKCS5Padding");
        System.out.println(sm2 + " " + sm3.digest("x".getBytes()).length + " " + sm4);
    }
}
