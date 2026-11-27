/*---[ test-quantum.c ]--------------------------------------------------
 * Experimental (FS_EXPERIMENTAL=ON): the placeholders refuse, and the
 * cipher-suite name lookup classifies.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>
#include "experimental/fs-quantum.h"

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

	/* The key and signature functions are placeholders with no
	 * cryptography behind them: every one must refuse. */
	{
		FsQuantumKeyPair kp;
		FsQuantumSignKeyPair sig_kp;
		guint8 ciphertext[1568] = { 0 };
		guint8 secret[32] = { 0 };
		guint8 signature[3293] = { 0 };
		gsize sig_len = sizeof (signature);
		const guint8 msg[] = "message";

		memset (&kp, 0, sizeof kp);
		memset (&sig_kp, 0, sizeof sig_kp);
		CHECK (!fs_quantum_generate_keypair (&kp), "placeholder: key generation refuses");
		CHECK (!fs_quantum_encapsulate (kp.public_key, ciphertext, secret), "placeholder: encapsulation refuses");
		CHECK (!fs_quantum_decapsulate (kp.secret_key, ciphertext, secret), "placeholder: decapsulation refuses");
		CHECK (!fs_quantum_sign_generate_keypair (&sig_kp), "placeholder: signing key generation refuses");
		CHECK (!fs_quantum_sign (sig_kp.sign_key, msg, sizeof msg, signature, &sig_len), "placeholder: signing refuses");
		CHECK (!fs_quantum_verify (sig_kp.verify_key, msg, sizeof msg, signature, sizeof signature), "placeholder: verification accepts nothing");
	}

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
