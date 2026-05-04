#!/usr/bin/env bash
# scripts/extract_cert.sh
# -----------------------------------------------
# Extract TLS certificate chain and prepare inputs
# for Task 6 (X.509 manual verification).
#
# Usage: bash scripts/extract_cert.sh [hostname]
# Default hostname: www.python.org

HOST="${1:-www.python.org}"
echo "[*] Downloading certificate chain from $HOST:443 ..."

# Download full chain — split into c0.pem (server) and c1.pem (issuer)
openssl s_client -connect "$HOST:443" -showcerts 2>/dev/null | \
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' | \
    awk 'BEGIN{n=0} /BEGIN CERT/{n++; file="c"(n-1)".pem"} {print > file}'

echo "[*] Saved c0.pem (server) and c1.pem (issuer)"

echo ""
echo "=== Issuer Public Key (n) ==="
openssl x509 -in c1.pem -noout -modulus | sed 's/Modulus=//'

echo ""
echo "=== Issuer Exponent (e) ==="
openssl x509 -in c1.pem -text -noout | grep Exponent

echo ""
echo "=== Server Certificate Signature ==="
openssl x509 -in c0.pem -text -noout | grep -A 50 "Signature Value:" | \
    grep ":" | tr -d ' :' | tr -d '\n'
echo ""

echo ""
echo "=== Extracting certificate body ==="
openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout
sha256sum c0_body.bin
echo "[*] Certificate body hash saved."
