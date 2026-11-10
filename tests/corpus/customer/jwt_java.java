import java.security.KeyPairGenerator;
public class Jwt {
    void key() throws Exception {
        KeyPairGenerator.getInstance("RSA").initialize(2048);
    }
}
