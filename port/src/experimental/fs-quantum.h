/*---[ fs-quantum.h ]-----------------------------------------------------
 * EXPERIMENTAL -- NOT post-quantum cryptography, and not shipped.
 *
 * The key and signature functions here are placeholders: they return
 * FALSE and produce nothing, because no ML-KEM (Kyber) or ML-DSA
 * (Dilithium) implementation is in this tree.  Do not build a security
 * feature on them.  fs_quantum_audit_cipher_suite classifies a cipher
 * suite by its NAME only; it looks at no traffic.
 * Built only with -DFS_EXPERIMENTAL=ON (src/experimental/README.md).
 *--------------------------------------------------------------------*/
#ifndef FS_QUANTUM_H
#define FS_QUANTUM_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
	guint8 public_key[1184];  /* Kyber-1024 public key size */
	guint8 secret_key[2400];  /* Kyber-1024 secret key size */
} FsQuantumKeyPair;

typedef struct
{
	guint8 verify_key[1952];  /* Dilithium-5 public verification key */
	guint8 sign_key[4016];    /* Dilithium-5 private signing key */
} FsQuantumSignKeyPair;

typedef enum
{
	FS_QUANTUM_SUITE_UNKNOWN = 0,
	FS_QUANTUM_SUITE_TLS_AES_256_GCM_SHA384,
	FS_QUANTUM_SUITE_TLS_CHACHA20_POLY1305_SHA256,
	FS_QUANTUM_SUITE_KYBER_MLKEM_AES_256,       /* Post-quantum hybrid KEM */
	FS_QUANTUM_SUITE_FALCON_DILITHIUM_HYBRID  /* Post-quantum hybrid signature */
} FsQuantumCipherSuite;

typedef enum
{
	FS_QUANTUM_RISK_SECURE = 0,               /* Fully quantum-resistant */
	FS_QUANTUM_RISK_HYBRID,                   /* Hybrid classical + quantum-resistant */
	FS_QUANTUM_RISK_VULNERABLE_RSA,           /* Vulnerable to Shor's algorithm (RSA) */
	FS_QUANTUM_RISK_VULNERABLE_ECDH           /* Vulnerable to Shor's algorithm (ECDH/ECDSA) */
} FsQuantumRiskLevel;

typedef struct
{
	FsQuantumCipherSuite suite;
	const gchar *name;
	FsQuantumRiskLevel risk_level;
	gboolean is_post_quantum;
	gboolean is_hybrid;
	const gchar *description;
} FsQuantumCipherAuditResult;

/* Placeholders: each returns FALSE and writes nothing (see above). */
gboolean fs_quantum_generate_keypair (FsQuantumKeyPair *out_keypair);

gboolean fs_quantum_encapsulate (const guint8 *pub_key, guint8 *out_ciphertext, guint8 *out_shared_secret);

gboolean fs_quantum_decapsulate (const guint8 *sec_key, const guint8 *ciphertext, guint8 *out_shared_secret);

gboolean fs_quantum_sign_generate_keypair (FsQuantumSignKeyPair *out_sign_keypair);

gboolean fs_quantum_sign (const guint8 *sign_key, const guint8 *message, gsize message_len, guint8 *out_signature, gsize *out_sig_len);

gboolean fs_quantum_verify (const guint8 *verify_key, const guint8 *message, gsize message_len, const guint8 *signature, gsize sig_len);

/* --- Cipher suite classification by name --- */

/* Audit a TLS cipher suite ID or string representation for quantum vulnerability */
FsQuantumCipherAuditResult fs_quantum_audit_cipher_suite (const gchar *suite_name_or_hex);

/* Tag connection or endpoint metadata with quantum risk assessment */
gboolean fs_quantum_tag_vulnerability (const gchar *endpoint_or_peer, FsQuantumCipherSuite suite, gchar *out_tag_buffer, gsize tag_buffer_len);

G_END_DECLS

#endif /* FS_QUANTUM_H */
