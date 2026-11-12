/*---[ fs-quantum.h ]-----------------------------------------------------
 * Post-Quantum Cryptography (PQC) Transport Security & Key Encapsulation
 * Part of StockFW Ultimate Extension (NIST PQC Aligned)
 *
 * Implements lattice-based post-quantum cryptographic primitives (CRYSTALS-Kyber
 * and Dilithium wrappers) for quantum-safe peer-to-peer mesh encapsulation.
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

/* Generate a post-quantum cryptographic keypair for secure tunnel encapsulation */
gboolean fs_quantum_generate_keypair (FsQuantumKeyPair *out_keypair);

/* Encapsulate a quantum-safe shared secret */
gboolean fs_quantum_encapsulate (const guint8 *pub_key, guint8 *out_ciphertext, guint8 *out_shared_secret);

/* Decapsulate a quantum-safe shared secret */
gboolean fs_quantum_decapsulate (const guint8 *sec_key, const guint8 *ciphertext, guint8 *out_shared_secret);

/* Generate a post-quantum digital signature keypair (CRYSTALS-Dilithium) */
gboolean fs_quantum_sign_generate_keypair (FsQuantumSignKeyPair *out_sign_keypair);

/* Sign message using post-quantum signature */
gboolean fs_quantum_sign (const guint8 *sign_key, const guint8 *message, gsize message_len, guint8 *out_signature, gsize *out_sig_len);

/* Verify post-quantum signature */
gboolean fs_quantum_verify (const guint8 *verify_key, const guint8 *message, gsize message_len, const guint8 *signature, gsize sig_len);

G_END_DECLS

#endif /* FS_QUANTUM_H */

