## RSA Lab — Makefile
## Compile all tasks: make all
## Compile single:    make task1
## Clean:             make clean

CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LIBS    = -lssl -lcrypto

SRCDIR  = src
BINDIR  = bin

TASKS   = task1_keygen task2_encrypt task3_decrypt \
          task4_sign task5_verify task6_x509

all: $(BINDIR) $(TASKS)

$(BINDIR):
	mkdir -p $(BINDIR)

task1_keygen: $(SRCDIR)/task1_keygen.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

task2_encrypt: $(SRCDIR)/task2_encrypt.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

task3_decrypt: $(SRCDIR)/task3_decrypt.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

task4_sign: $(SRCDIR)/task4_sign.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

task5_verify: $(SRCDIR)/task5_verify.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

task6_x509: $(SRCDIR)/task6_x509.c
	$(CC) $(CFLAGS) -o $(BINDIR)/$@ $< $(LIBS)

run-all: all
	@echo "\n>>> Task 1: Key Derivation"       && ./$(BINDIR)/task1_keygen
	@echo "\n>>> Task 2: Encryption"           && ./$(BINDIR)/task2_encrypt
	@echo "\n>>> Task 3: Decryption"           && ./$(BINDIR)/task3_decrypt
	@echo "\n>>> Task 4: Digital Signature"    && ./$(BINDIR)/task4_sign
	@echo "\n>>> Task 5: Signature Verify"     && ./$(BINDIR)/task5_verify
	@echo "\n>>> Task 6: X.509 Certificate"    && ./$(BINDIR)/task6_x509

clean:
	rm -rf $(BINDIR)

.PHONY: all run-all clean
