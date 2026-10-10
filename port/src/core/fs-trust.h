/*---[ fs-trust.h ]------------------------------------------------------
 * Application trust engine.
 *
 * Priority 1 of the copilot roadmap: identify signed versus unsigned
 * executables, hash them, name the publisher, and notice when a file
 * that was attested before has since changed underneath us.
 *
 * The engine is split along the same seam as everything else: this
 * half is portable data work -- SHA-256, file facts, the baseline
 * store, the assessment -- and never includes an OS header.  The one
 * platform call (Authenticode) arrives through a provider callback
 * that the backend vtable supplies; tests install their own.
 *--------------------------------------------------------------------*/
#ifndef FS_TRUST_H
#define FS_TRUST_H

#include <glib.h>

G_BEGIN_DECLS

/* What the signature check found. */
typedef enum
{
	/* The file is an executable, but no platform provider was
	 * installed (a test binary, a backend without Authenticode) --
	 * nobody asked, so nobody answers. */
	FS_TRUST_SIG_UNKNOWN = 0,

	/* Authenticode verified: intact signature, chain stands. */
	FS_TRUST_SIG_VALID,

	/* There is a signature but it does not stand: bad digest
	 * (somebody edited the binary), expired, untrusted root,
	 * explicit distrust.  The interesting negative. */
	FS_TRUST_SIG_INVALID,

	/* An executable with no signature at all. */
	FS_TRUST_SIG_UNSIGNED,

	/* Not a Windows executable (no "MZ" header): hashing it still
	 * makes sense, signing does not. */
	FS_TRUST_SIG_NOT_APPLICABLE
} FsTrustSignature;

/* One file's report.  All strings owned by the report. */
typedef struct
{
	gchar *path;                /* as inspected */
	guint64 size;
	gint64 mtime;               /* unix seconds, 0 when unknown */
	gchar *sha256;              /* lowercase hex, always present */
	gboolean executable;        /* MZ header seen in the first bytes */
	FsTrustSignature sig;
	gchar *publisher;           /* signer's display name, or NULL */
} FsTrustReport;

/* The platform's signature provider: answer TRUE with *out_sig and
 * optionally *out_publisher set, or FALSE when the platform cannot
 * say.  The provider must not write files or raise UI. */
typedef gboolean (*FsTrustSignatureFunc) (const gchar *path,
                                          FsTrustSignature *out_sig,
                                          gchar **out_publisher,
                                          gpointer user_data);

/* Install (or clear with fn == NULL) the provider.  The app does this
 * once at startup from the backend vtable; tests do it with their
 * own fakes.  No refcount: one global slot by design. */
void fs_trust_set_signature_provider (FsTrustSignatureFunc fn,
                                      gpointer user_data);

/* Inspect one file: size, mtime, SHA-256, executable-ness, and the
 * signature through whatever provider is installed.  Returns NULL
 * with *error set when the file cannot be read at all -- a report
 * means the hash was computed. */
FsTrustReport *fs_trust_inspect (const gchar *path, GError **error);
void fs_trust_report_free (FsTrustReport *report);

/* Human label for a signature state: "Signed and verified",
 * "Signed but invalid", "Not signed", "Not an executable",
 * "Signature not checked".  Translatable at the caller. */
const gchar *fs_trust_sig_name (FsTrustSignature sig);

/* How today's file relates to the attested baseline. */
typedef enum
{
	FS_TRUST_CHANGE_NEW,        /* never attested */
	FS_TRUST_CHANGE_UNCHANGED,  /* bytes match the baseline */
	FS_TRUST_CHANGE_CHANGED,    /* same path, different bytes: the
	                             * "unexpected change" P1 exists for */
	FS_TRUST_CHANGE_GONE,       /* attested before, now missing */
	FS_TRUST_CHANGE_UNREADABLE  /* file could not be read at all */
} FsTrustChange;

/* One assessment: the file's report (NULL when unreadable) next to
 * what the baseline says it used to be. */
typedef struct
{
	gchar *path;
	FsTrustReport *report;      /* NULL unless the file was read */
	FsTrustChange change;
	gchar *baseline_sha256;     /* attested hash, NULL when NEW */
	gchar *baseline_publisher;  /* attested signer, NULL when NEW */
} FsTrustAssessment;

void fs_trust_assessment_free (FsTrustAssessment *assessment);

/* The attested baseline: path -> hash last confirmed by the user.
 * CSV on disk, quoted so paths and publisher names may hold commas. */
typedef struct _FsTrustStore FsTrustStore;

/* Where the store lives: $STOCKFW_TRUST_FILE when set, otherwise
 * trust.csv in the config directory.  Caller frees. */
gchar *fs_trust_store_path (void);

FsTrustStore *fs_trust_store_new (const gchar *csv_path);

/* Read the store.  A missing file is an empty store, a malformed
 * line is skipped: a trust baseline must not refuse to load over one
 * bad row.  Never NULL unless csv_path is NULL. */
FsTrustStore *fs_trust_store_load (const gchar *csv_path);

void fs_trust_store_free (FsTrustStore *store);

const gchar *fs_trust_store_file (FsTrustStore *store);
guint fs_trust_store_count (FsTrustStore *store);

/* Compare the file at `path' against the baseline.  Never NULL:
 * every outcome is a row the caller can show.  Paths compare
 * ASCII-case-insensitively -- Windows paths do, and the store only
 * ever holds Windows paths. */
FsTrustAssessment *fs_trust_assess (FsTrustStore *store,
                                    const gchar *path);

/* Record (or re-confirm) a report in the baseline and append an
 * audit line.  Returns FALSE when the report or its hash is missing
 * or the store has no file to remember. */
gboolean fs_trust_attest (FsTrustStore *store,
                          const FsTrustReport *report);

/* Forget a path (audit line included).  TRUE when it was there. */
gboolean fs_trust_remove (FsTrustStore *store, const gchar *path);

/* Write the store back, atomically. */
gboolean fs_trust_store_save (FsTrustStore *store, GError **error);

#ifdef _WIN32
/* The Authenticode provider, implemented over WinVerifyTrust +
 * CryptQueryObject in src/platform/windows/fs-trust-win.c and wired
 * into the backend vtable by the Windows backend. */
gboolean fs_trust_win_signature (const gchar *path,
                                 FsTrustSignature *out_sig,
                                 gchar **out_publisher);
#endif

G_END_DECLS

#endif /* FS_TRUST_H */
