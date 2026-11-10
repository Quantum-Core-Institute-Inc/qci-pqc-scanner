// Java real-world style
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;

public class RealWorldJava {
    void classical() throws Exception {
        KeyPairGenerator.getInstance("RSA");
        Signature.getInstance("SHA256withECDSA");
    }
    void pqc() throws Exception {
        KeyPairGenerator.getInstance("ML-KEM");
        // MLKEMParameterSpec.ml_kem_768
        Signature.getInstance("ML-DSA");
    }
}
