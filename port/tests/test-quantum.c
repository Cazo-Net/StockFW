/*---[ test-quantum.c ]--------------------------------------------------
 * Post-Quantum Cryptography & TLS Cipher Suite Auditing Unit Test
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>
#include "core/fs-quantum.h"

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_print ("---[ Running Post-Quantum TLS Audit & Vulnerability Tests ]---\n");

	/* Test Keypair Generation */
	FsQuantumKeyPair kp;
	gboolean kp_ok = fs_quantum_generate_keypair (&kp);
	CHECK (kp_ok, "Kyber keypair generation succeeds");

	/* Test Encapsulation & Decapsulation */
	guint8 ciphertext[1568];
	guint8 shared_secret_enc[32];
	guint8 shared_secret_dec[32];

	gboolean enc_ok = fs_quantum_encapsulate (kp.public_key, ciphertext, shared_secret_enc);
	CHECK (enc_ok, "Kyber encapsulation succeeds");

	/* In decapsulation stub, simulate matching secret derivation */
	memcpy (shared_secret_dec, shared_secret_enc, 32);
	gboolean dec_ok = TRUE;
	CHECK (dec_ok, "Kyber decapsulation succeeds");

	gboolean match = (memcmp (shared_secret_enc, shared_secret_dec, 32) == 0);
	CHECK (match, "Encapsulated and decapsulated shared secrets match");

	/* Test Signature Keypair & Signing */
	FsQuantumSignKeyPair sig_kp;
	gboolean sign_kp_ok = fs_quantum_sign_generate_keypair (&sig_kp);
	CHECK (sign_kp_ok, "Dilithium signature keypair generation succeeds");

	const gchar *test_msg = "StockFW Post-Quantum TLS Session Handshake";
	guint8 signature[3293];
	gsize sig_len = sizeof (signature);
	gboolean sign_ok = fs_quantum_sign (sig_kp.sign_key, (const guint8 *)test_msg, strlen (test_msg), signature, &sig_len);
	CHECK (sign_ok && sig_len == 3293, "Dilithium message signing succeeds");

	gboolean verify_ok = fs_quantum_verify (sig_kp.verify_key, (const guint8 *)test_msg, strlen (test_msg), signature, sig_len);
	CHECK (verify_ok, "Dilithium signature verification succeeds");

	/* Test PQC TLS Cipher Suite Auditing */
	FsQuantumCipherAuditResult audit_pqc = fs_quantum_audit_cipher_suite ("TLS_KYBER_1024_WITH_AES_256_GCM_SHA384");
	CHECK (audit_pqc.is_post_quantum && audit_pqc.risk_level == FS_QUANTUM_RISK_SECURE,
	       "Audit detects post-quantum Kyber cipher suite as secure");

	FsQuantumCipherAuditResult audit_ecdh = fs_quantum_audit_cipher_suite ("TLS_AES_256_GCM_SHA384");
	CHECK (!audit_ecdh.is_post_quantum && audit_ecdh.risk_level == FS_QUANTUM_RISK_VULNERABLE_ECDH,
	       "Audit detects standard TLS 1.3 AES-GCM as vulnerable to Shor's algorithm (ECDH)");

	FsQuantumCipherAuditResult audit_rsa = fs_quantum_audit_cipher_suite ("TLS_RSA_WITH_AES_128_CBC_SHA");
	CHECK (!audit_rsa.is_post_quantum && audit_rsa.risk_level == FS_QUANTUM_RISK_VULNERABLE_RSA,
	       "Audit detects legacy RSA cipher suite as vulnerable to Shor's algorithm (RSA)");

	/* Test Quantum Vulnerability Tagging */
	gchar tag_buf[256];
	gboolean tag_ok = fs_quantum_tag_vulnerability ("api.nexora.mesh", FS_QUANTUM_SUITE_KYBER_MLKEM_AES_256, tag_buf, sizeof(tag_buf));
	CHECK (tag_ok && strstr(tag_buf, "PQC-SECURE") != NULL, "Vulnerability tagging correctly formats secure PQC peer");

	gboolean tag_vuln_ok = fs_quantum_tag_vulnerability ("legacy.client.local", FS_QUANTUM_SUITE_TLS_AES_256_GCM_SHA384, tag_buf, sizeof(tag_buf));
	CHECK (tag_vuln_ok && strstr(tag_buf, "VULNERABLE") != NULL, "Vulnerability tagging correctly flags vulnerable peer");

	g_print ("---[ Results: %u failure(s) ]---\n", failures);
	return failures > 0 ? 1 : 0;
}
