/*---[ fs-quantum.c ]-----------------------------------------------------
 * EXPERIMENTAL -- NOT post-quantum cryptography, and not shipped.
 *
 * Two parts.  The key-encapsulation and signature functions are
 * placeholders that refuse every call (see below).  The cipher-suite
 * "audit" is a name lookup: it classifies a suite by words in its name
 * and inspects no connection.  Built only with FS_EXPERIMENTAL=ON.
 *--------------------------------------------------------------------*/

#include "experimental/fs-quantum.h"
#include <string.h>
#include <stdio.h>

/* None of the six functions below does any cryptography, so each one
 * refuses (returns FALSE) and writes nothing.  The 1.0.9 versions
 * "succeeded" with random bytes for keys, an XOR for the shared secret
 * and a verify that accepted every signature; code that trusted them
 * would have had no protection at all.  A real implementation should
 * call a reviewed library (liboqs, or OpenSSL 3.5's ML-KEM / ML-DSA). */

gboolean
fs_quantum_generate_keypair (FsQuantumKeyPair *out_keypair)
{
	(void) out_keypair;
	return FALSE;
}

gboolean
fs_quantum_encapsulate (const guint8 *pub_key, guint8 *out_ciphertext, guint8 *out_shared_secret)
{
	(void) pub_key; (void) out_ciphertext; (void) out_shared_secret;
	return FALSE;
}

gboolean
fs_quantum_decapsulate (const guint8 *sec_key, const guint8 *ciphertext, guint8 *out_shared_secret)
{
	(void) sec_key; (void) ciphertext; (void) out_shared_secret;
	return FALSE;
}

gboolean
fs_quantum_sign_generate_keypair (FsQuantumSignKeyPair *out_sign_keypair)
{
	(void) out_sign_keypair;
	return FALSE;
}

gboolean
fs_quantum_sign (const guint8 *sign_key, const guint8 *message, gsize message_len, guint8 *out_signature, gsize *out_sig_len)
{
	(void) sign_key; (void) message; (void) message_len;
	(void) out_signature; (void) out_sig_len;
	return FALSE;
}

gboolean
fs_quantum_verify (const guint8 *verify_key, const guint8 *message, gsize message_len, const guint8 *signature, gsize sig_len)
{
	(void) verify_key; (void) message; (void) message_len;
	(void) signature; (void) sig_len;
	return FALSE;
}

/* --- Cipher suite classification by name, and the tag built from it --- */

FsQuantumCipherAuditResult
fs_quantum_audit_cipher_suite (const gchar *suite_name_or_hex)
{
	FsQuantumCipherAuditResult result = {
		.suite = FS_QUANTUM_SUITE_UNKNOWN,
		.name = "UNKNOWN",
		.risk_level = FS_QUANTUM_RISK_VULNERABLE_RSA,
		.is_post_quantum = FALSE,
		.is_hybrid = FALSE,
		.description = "Unrecognized or insecure cipher suite"
	};

	if (!suite_name_or_hex || *suite_name_or_hex == '\0') {
		return result;
	}

	gchar *lower = g_ascii_strdown (suite_name_or_hex, -1);

	if (strstr (lower, "kyber") != NULL || strstr (lower, "ml-kem") != NULL || strstr (lower, "pqc") != NULL) {
		result.suite = FS_QUANTUM_SUITE_KYBER_MLKEM_AES_256;
		result.name = "TLS_KYBER_1024_WITH_AES_256_GCM_SHA384";
		result.risk_level = FS_QUANTUM_RISK_SECURE;
		result.is_post_quantum = TRUE;
		result.is_hybrid = TRUE;
		result.description = "NIST PQC Aligned Lattice-based Kyber-1024 / ML-KEM Hybrid Key Encapsulation (Quantum Secure)";
	} else if (strstr (lower, "falcon") != NULL || strstr (lower, "dilithium") != NULL) {
		result.suite = FS_QUANTUM_SUITE_FALCON_DILITHIUM_HYBRID;
		result.name = "TLS_DILITHIUM_5_WITH_AES_256_GCM_SHA384";
		result.risk_level = FS_QUANTUM_RISK_SECURE;
		result.is_post_quantum = TRUE;
		result.is_hybrid = TRUE;
		result.description = "NIST PQC Aligned CRYSTALS-Dilithium-5 Post-Quantum Signature Suite (Quantum Secure)";
	} else if (strstr (lower, "aes_256_gcm") != NULL || strstr (lower, "aes256-gcm") != NULL || strstr (lower, "0x13,0x02") != NULL) {
		result.suite = FS_QUANTUM_SUITE_TLS_AES_256_GCM_SHA384;
		result.name = "TLS_AES_256_GCM_SHA384";
		result.risk_level = FS_QUANTUM_RISK_VULNERABLE_ECDH;
		result.is_post_quantum = FALSE;
		result.is_hybrid = FALSE;
		result.description = "Standard TLS 1.3 Cipher Suite (Vulnerable to Shor's Algorithm via underlying ECDHE key exchange)";
	} else if (strstr (lower, "chacha20") != NULL || strstr (lower, "0x13,0x03") != NULL) {
		result.suite = FS_QUANTUM_SUITE_TLS_CHACHA20_POLY1305_SHA256;
		result.name = "TLS_CHACHA20_POLY1305_SHA256";
		result.risk_level = FS_QUANTUM_RISK_VULNERABLE_ECDH;
		result.is_post_quantum = FALSE;
		result.is_hybrid = FALSE;
		result.description = "Standard TLS 1.3 ChaCha20 Suite (Vulnerable to Shor's Algorithm via underlying ECDHE key exchange)";
	} else if (strstr (lower, "rsa") != NULL || strstr (lower, "cbc") != NULL) {
		result.suite = FS_QUANTUM_SUITE_UNKNOWN;
		result.name = "Legacy_RSA_Cipher";
		result.risk_level = FS_QUANTUM_RISK_VULNERABLE_RSA;
		result.is_post_quantum = FALSE;
		result.is_hybrid = FALSE;
		result.description = "Legacy RSA / CBC Cipher Suite (Highly vulnerable to both classical and quantum attacks)";
	} else {
		result.suite = FS_QUANTUM_SUITE_TLS_AES_256_GCM_SHA384;
		result.name = suite_name_or_hex;
		result.risk_level = FS_QUANTUM_RISK_VULNERABLE_ECDH;
		result.is_post_quantum = FALSE;
		result.is_hybrid = FALSE;
		result.description = "Standard cipher suite relying on classical key exchange (Shor vulnerable)";
	}

	g_free (lower);
	return result;
}

gboolean
fs_quantum_tag_vulnerability (const gchar *endpoint_or_peer, FsQuantumCipherSuite suite, gchar *out_tag_buffer, gsize tag_buffer_len)
{
	if (!endpoint_or_peer || !out_tag_buffer || tag_buffer_len < 64) {
		return FALSE;
	}

	FsQuantumCipherAuditResult audit = fs_quantum_audit_cipher_suite (
		suite == FS_QUANTUM_SUITE_KYBER_MLKEM_AES_256 ? "kyber" :
		suite == FS_QUANTUM_SUITE_FALCON_DILITHIUM_HYBRID ? "dilithium" : "aes_256_gcm"
	);

	const gchar *risk_label = "SECURE";
	switch (audit.risk_level) {
		case FS_QUANTUM_RISK_SECURE: risk_label = "PQC-SECURE"; break;
		case FS_QUANTUM_RISK_HYBRID: risk_label = "HYBRID-SECURE"; break;
		case FS_QUANTUM_RISK_VULNERABLE_RSA: risk_label = "VULNERABLE-RSA-SHOR"; break;
		case FS_QUANTUM_RISK_VULNERABLE_ECDH: risk_label = "VULNERABLE-ECDH-SHOR"; break;
	}

	g_snprintf (out_tag_buffer, tag_buffer_len, "[QUANTUM-TAG:%s] Peer: %s | Suite: %s | Risk: %s",
	            risk_label, endpoint_or_peer, audit.name, audit.description);

	return TRUE;
}
