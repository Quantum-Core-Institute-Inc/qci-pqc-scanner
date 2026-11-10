#include <openssl/evp.h>
void f(void) {
    EVP_md5();
    EVP_sha256();
    EVP_aes_128_ecb();
    RSA_generate_key(2048, 65537, 0, 0);
}
