public class CryptoExample {
    public void doCrypto() {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Signature s = Signature.getInstance("SHA256withRSA");
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
