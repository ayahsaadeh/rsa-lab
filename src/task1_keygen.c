/**
 * Task 1: RSA Private Key Derivation
 * -----------------------------------
 * Given prime factors p, q and public exponent e,
 * compute the RSA private key d such that:
 *   (e * d) ≡ 1 (mod φ(n))
 *
 * Steps:
 *   1. n   = p × q
 *   2. φ(n) = (p-1)(q-1)
 *   3. d   = e⁻¹ mod φ(n)   [modular inverse]
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

    BIGNUM *p    = BN_new();
    BIGNUM *q    = BN_new();
    BIGNUM *e    = BN_new();
    BIGNUM *n    = BN_new();
    BIGNUM *phi  = BN_new();
    BIGNUM *d    = BN_new();
    BIGNUM *sub1 = BN_new();
    BIGNUM *sub2 = BN_new();

    /* Assign values */
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    /* n = p * q */
    BN_mul(n, p, q, ctx);

    /* φ(n) = (p-1)(q-1) */
    BN_sub(sub1, p, BN_value_one());
    BN_sub(sub2, q, BN_value_one());
    BN_mul(phi, sub1, sub2, ctx);

    /* d = e⁻¹ mod φ(n) */
    BN_mod_inverse(d, e, phi, ctx);

    /* Results */
    printf("\n=== RSA Key Generation ===\n\n");
    printBN("p             =", p);
    printBN("q             =", q);
    printBN("n   (p*q)     =", n);
    printBN("φ(n)          =", phi);
    printBN("e             =", e);
    printBN("d (priv. key) =", d);
    printf("\n");

    BN_free(p); BN_free(q); BN_free(e);
    BN_free(n); BN_free(phi); BN_free(d);
    BN_free(sub1); BN_free(sub2);
    BN_CTX_free(ctx);

    return 0;
}
