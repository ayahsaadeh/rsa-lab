/**
 * Task 6: Manual X.509 Certificate Verification
 * -----------------------------------------------
 * Manually verify a real TLS certificate from www.python.org
 * using the issuer's RSA public key.
 *
 * Steps performed externally (see scripts/extract_cert.sh):
 *   1. Download certificate chain via openssl s_client
 *   2. Extract issuer public key (e, n) from c1.pem
 *   3. Extract server certificate signature from c0.pem
 *   4. Extract certificate body hash: sha256(c0_body.bin)
 *
 * This program verifies:
 *   decrypted_s == SHA-256 hash of certificate body
 *
 * Issuer: GlobalSign Atlas R3 DV TLS CA 2024 Q2
 * Server: www.python.org
 */

#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBNhex(const char *msg, const BIGNUM *a) {
    char *hex = BN_bn2hex(a);
    printf("%s %s\n", msg, hex);
    OPENSSL_free(hex);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n    = BN_new();
    BIGNUM *e    = BN_new();
    BIGNUM *s    = BN_new();
    BIGNUM *m    = BN_new();   /* expected: SHA-256 of cert body */
    BIGNUM *decs = BN_new();   /* decrypted signature */

    /* Issuer public key extracted from c1.pem */
    BN_hex2bn(&n,
        "8BE6F39245879FD1417872761FC627B6ECAC8A5B89383BE2B5F9193F8C"
        "B5256027D1AA87EC2F18F4C7CEEB8987DB1FF7C5605DC2D945554BDCCBC31B5"
        "0E5ECD070CCC3ECCD9FA8135A373E720EC91CD5E86B1C314A0F2CC254EA6833"
        "6CCD734DC326D7320B1C9976D5CC15F3A3AFC11B01D1424FBD4F78D356513911"
        "912484E441717F373E6542EEB0917910DC6B33A489D9AA87FC9B0BB83DAAC283"
        "03DF214A46DB863EAC20D5EB3654C3D8848DC8E8DBD16CA585CD9FAD765613"
        "2225188F1AFBB56DFDC6F60A6A34CBA2A1F357EDFBC44084D5F10C1BF5C6677"
        "55C649604B101A7E2820FAB10253B1C10E0490688A03360E1B5B4A7ECFB910F2F"
        "A51C89B9C3");
    BN_hex2bn(&e, "010001");   /* 65537 */

    /* Server certificate signature extracted from c0.pem */
    BN_hex2bn(&s,
        "08329fe29b3a0d08065b4a6694961a9e5249a34808f3f7e267901fe050dc6bfbe238df55"
        "9a482e76952472268c35f71399af72c3b0019377ffb60c3b78448efb467f790bdf9898a1"
        "01d1218449f11f6c98e14c6bae642ba414595007ceee847121826a277fb19cc8e6d3551f"
        "dca7d345cf4d30c112c84e75dcbd74352d2b257e05f3b653a515baa7b3be6de729dab7ca"
        "d2c1e02d8a54c92c1ea79194cd8dd3c4d1d689db03acf3c6aa03c2e5b6c070c13a9a6507"
        "2af10b594f5a1e38549d0ab0004b38711d0fcd1eef9fc4ecc81ad2ac6939c3e250d2c993"
        "ab3d446439a14ae7a32144b230701b80b80a909111cdb70c2c863d20d8b21c10c2ecd4b8"
        "382262c7");

    /* Expected: SHA-256 hash of c0_body.bin (certificate body) */
    BN_hex2bn(&m, "13f5c5878b0ae14e94e7e3c6dc4b62e7f5c8b6d198ebaf17e14ea0c04afadd90");

    /* Decrypt signature: decs = s^e mod n */
    BN_mod_exp(decs, s, e, n, ctx);

    printf("\n=== X.509 Certificate Verification (www.python.org) ===\n\n");
    printBNhex("Decrypted s        =", decs);

    /* Mask to 256 bits to extract the embedded hash */
    BN_mask_bits(decs, NBITS);
    printBNhex("Decrypted s (256b) =", decs);
    printBNhex("Certificate body   =", m);

    if (BN_cmp(decs, m) == 0)
        printf("\nResult: CERTIFICATE VALID — Signature matches certificate body hash.\n\n");
    else
        printf("\nResult: MISMATCH — Verification failed.\n\n");

    BN_free(n); BN_free(e); BN_free(s);
    BN_free(m); BN_free(decs);
    BN_CTX_free(ctx);

    return 0;
}
