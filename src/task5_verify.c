/**
 * Task 5: Signature Verification
 * --------------------------------
 * Bob verifies Alice's signature using her public key (e, n):
 *   M_verify = S^e mod n
 *   Valid iff M_verify == M
 *
 * Also demonstrates that altering even a single bit of the
 * signature causes verification to fail.
 *
 * Message: "Launch a missile."
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

    BIGNUM *n        = BN_new();
    BIGNUM *e        = BN_new();
    BIGNUM *M        = BN_new();
    BIGNUM *S        = BN_new();
    BIGNUM *M_verify = BN_new();

    /* Alice's public key */
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    /* Original signature (valid) */
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    /* "Launch a missile." in hex */
    BN_hex2bn(&M, "4c61756e63206120646973736e696c652e");

    /* Verify: M_verify = S^e mod n */
    BN_mod_exp(M_verify, S, e, n, ctx);

    printf("\n=== RSA Signature Verification ===\n\n");
    printBN("Original message (M)      =", M);
    printBN("Signature (S)             =", S);
    printBN("Decrypted signature       =", M_verify);

    if (BN_cmp(M_verify, M) == 0)
        printf("Result: VERIFIED — Message is from Alice.\n");
    else
        printf("Result: FAILED  — Message is NOT from Alice.\n");

    /* --- Tamper: flip last byte 2F -> 3F --- */
    printf("\n--- Tampered signature (last byte 2F → 3F) ---\n\n");
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_mod_exp(M_verify, S, e, n, ctx);
    printBN("Decrypted tampered sig    =", M_verify);

    if (BN_cmp(M_verify, M) == 0)
        printf("Result: VERIFIED — Message is from Alice.\n\n");
    else
        printf("Result: FAILED  — Signature verification failed. Message tampered!\n\n");

    BN_free(n); BN_free(e); BN_free(M);
    BN_free(S); BN_free(M_verify);
    BN_CTX_free(ctx);

    return 0;
}
