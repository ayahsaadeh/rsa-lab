/**
 * Task 2: RSA Encryption
 * ----------------------
 * Encrypt message M using public key (e, n):
 *   C = M^e mod n
 *
 * Message: "A top secret!"
 * Hex:      4120746f702073656372657421
 */

#include <stdio.h>
#include <openssl/bn.h>

void printBN(const char *msg, const BIGNUM *a) {
    char *hex = BN_bn2hex(a);
    printf("%s %s\n", msg, hex);
    OPENSSL_free(hex);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *M = BN_new();
    BIGNUM *C = BN_new();

    /* Public key */
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");   /* 65537 */

    /* Plaintext: "A top secret!" in hex */
    BN_hex2bn(&M, "4120746F702073656372657421");

    /* C = M^e mod n */
    BN_mod_exp(C, M, e, n, ctx);

    printf("\n=== RSA Encryption ===\n\n");
    printBN("Plaintext  M  =", M);
    printBN("Ciphertext C  =", C);
    printf("\n");

    BN_free(n); BN_free(e); BN_free(M); BN_free(C);
    BN_CTX_free(ctx);

    return 0;
}
