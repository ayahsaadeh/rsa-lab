/**
 * Task 3: RSA Decryption
 * ----------------------
 * Decrypt ciphertext C using private key (d, n):
 *   M = C^d mod n
 *
 * Decoded plaintext: "Password is dees"
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

    BIGNUM *n          = BN_new();
    BIGNUM *d          = BN_new();
    BIGNUM *ciphertext = BN_new();
    BIGNUM *decrypted  = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&ciphertext, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    /* M = C^d mod n */
    BN_mod_exp(decrypted, ciphertext, d, n, ctx);

    printf("\n=== RSA Decryption ===\n\n");
    printBN("Ciphertext (C)  =", ciphertext);
    printBN("Decrypted  (M)  =", decrypted);
    printf("\nConvert to ASCII: python3 -c 'print(bytes.fromhex(\"...\").decode(\"utf-8\"))'\n\n");

    BN_free(n); BN_free(d);
    BN_free(ciphertext); BN_free(decrypted);
    BN_CTX_free(ctx);

    return 0;
}
