/**
 * Task 4: Digital Signature — Sign a Message
 * -------------------------------------------
 * Sign message M with private key (d, n):
 *   S = M^d mod n
 *
 * Demonstrates avalanche effect: a 1-byte change in the message
 * produces a completely different signature.
 *
 * M1: "I owe you $2000."
 * M2: "I owe you $3000."
 */

#include <stdio.h>
#include <openssl/bn.h>

void printBNhex(const char *msg, const BIGNUM *a) {
    char *hex = BN_bn2hex(a);
    printf("%s %s\n", msg, hex);
    OPENSSL_free(hex);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n     = BN_new();
    BIGNUM *d     = BN_new();
    BIGNUM *m2000 = BN_new();
    BIGNUM *m3000 = BN_new();
    BIGNUM *s2000 = BN_new();
    BIGNUM *s3000 = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    /* "I owe you $2000." → hex */
    BN_hex2bn(&m2000, "49206f776520796f752024323030302e");
    /* "I owe you $3000." → hex */
    BN_hex2bn(&m3000, "49206f776520796f752024333030302e");

    /* S = M^d mod n */
    BN_mod_exp(s2000, m2000, d, n, ctx);
    BN_mod_exp(s3000, m3000, d, n, ctx);

    printf("\n=== RSA Digital Signature ===\n\n");
    printBNhex("M  (I owe $2000) =", m2000);
    printBNhex("S  (sig $2000)   =", s2000);
    printf("\n");
    printBNhex("M  (I owe $3000) =", m3000);
    printBNhex("S  (sig $3000)   =", s3000);
    printf("\n[Observe] A single-byte change ($2000 → $3000) yields a completely different signature.\n\n");

    BN_free(n); BN_free(d);
    BN_free(m2000); BN_free(m3000);
    BN_free(s2000); BN_free(s3000);
    BN_CTX_free(ctx);

    return 0;
}
