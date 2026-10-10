/*---[ fs-trust-win.c ]--------------------------------------------------
 * Authenticode half of the trust engine, Windows edition.
 *
 * Two questions, two APIs: WinVerifyTrust answers "does the signature
 * stand on this machine", CryptQueryObject answers "who signed it".
 * Neither may touch the network -- the app runs unattended and a
 * revocation fetch that hangs would freeze the trust scan for a
 * timeout; revocation checks stay off and the verdict says only what
 * the file itself proves.
 *
 * Compiled into the backend target only (never into the portable
 * core or its tests), and wired into the FsBackend vtable.
 *--------------------------------------------------------------------*/
#include <string.h>

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>

#include "core/fs-trust.h"

/* WINTRUST_ACTION_GENERIC_VERIFY_V2 spelled out: taking the GUID from
 * the header would need INITGUID (and with it every other GUID those
 * headers carry).  The value is part of the public contract. */
static const GUID k_verify_policy = {
	0xaac56bcd, 0xcd44, 0x11d0,
	{ 0x8c, 0xe2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee }
};

/* The signer's display name, or NULL when there is no embedded
 * signer to name.  Print string, so a non-ASCII publisher converts
 * straight from UTF-16 without an ANSI detour. */
static gchar *
signer_publisher (const gchar *path)
{
	gchar *publisher = NULL;
	gunichar2 *wide_path;
	HCERTSTORE store = NULL;
	HCRYPTMSG msg = NULL;
	DWORD encoding = 0, content = 0, format = 0;

	wide_path = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
	if (wide_path == NULL)
		return NULL;

	if (!CryptQueryObject (CERT_QUERY_OBJECT_FILE, wide_path,
	                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
	                       CERT_QUERY_FORMAT_FLAG_BINARY, 0,
	                       &encoding, &content, &format,
	                       &store, &msg, NULL))
		goto out;

	{
		DWORD size = 0;
		DWORD count = 0;

		if (CryptMsgGetParam (msg, CMSG_SIGNER_COUNT_PARAM, 0,
		                      NULL, &size) &&
		    CryptMsgGetParam (msg, CMSG_SIGNER_COUNT_PARAM, 0,
		                      &count, &size) &&
		    count > 0) {
			PCMSG_SIGNER_INFO info = NULL;

			size = 0;
			if (CryptMsgGetParam (msg, CMSG_SIGNER_INFO_PARAM, 0,
			                      NULL, &size)) {
				info = (PCMSG_SIGNER_INFO) LocalAlloc (LMEM_FIXED,
				                                       size);
				if (info != NULL &&
				    CryptMsgGetParam (msg, CMSG_SIGNER_INFO_PARAM,
				                      0, info, &size)) {
					CERT_INFO subject;
					PCCERT_CONTEXT cert;

					/* The embedded signer is found the way
					 * the CMS message names it: issuer plus
					 * serial against the message store. */
					memset (&subject, 0, sizeof (subject));
					subject.Issuer = info->Issuer;
					subject.SerialNumber =
						info->SerialNumber;

					cert = CertFindCertificateInStore (
						store,
						X509_ASN_ENCODING |
						PKCS_7_ASN_ENCODING,
						0, CERT_FIND_SUBJECT_CERT,
						&subject, NULL);
					if (cert != NULL) {
						WCHAR name[256];
						DWORD n;

						n = CertGetNameStringW (
							cert,
							CERT_NAME_SIMPLE_DISPLAY_TYPE,
							0, NULL, name,
							G_N_ELEMENTS (name));
						if (n > 1)
							publisher =
								g_utf16_to_utf8 (
									name, -1,
									NULL, NULL,
									NULL);
						CertFreeCertificateContext (
							cert);
					}
				}
				if (info != NULL)
					LocalFree (info);
			}
		}
	}

out:
	if (msg != NULL)
		CryptMsgClose (msg);
	if (store != NULL)
		CertCloseStore (store, 0);
	g_free (wide_path);

	return publisher;
}

gboolean
fs_trust_win_signature (const gchar *path, FsTrustSignature *out_sig,
                        gchar **out_publisher)
{
	WINTRUST_FILE_INFO file;
	WINTRUST_DATA trust;
	GUID policy = k_verify_policy;
	gunichar2 *wide;
	LONG status;
	gboolean answered = FALSE;

	g_return_val_if_fail (out_sig != NULL && out_publisher != NULL,
	                      FALSE);

	*out_sig = FS_TRUST_SIG_UNKNOWN;
	*out_publisher = NULL;

	if (path == NULL || *path == '\0')
		return FALSE;

	wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
	if (wide == NULL)
		return FALSE;

	memset (&file, 0, sizeof (file));
	file.cbStruct    = sizeof (file);
	file.pcwszFilePath = (LPWSTR) wide;

	memset (&trust, 0, sizeof (trust));
	trust.cbStruct   = sizeof (trust);
	trust.dwUIChoice = WTD_UI_NONE;
	/* No revocation fetch, no URL retrieval: a verdict this machine
	 * can reach offline, or none at all. */
	trust.fdwRevocationChecks = WTD_REVOKE_NONE;
	trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
	trust.dwUnionChoice = WTD_CHOICE_FILE;
	trust.pFile = &file;
	/* dwStateAction stays IGNORE: the verdict needs no state object,
	 * and the publisher comes from CryptQueryObject below. */

	status = WinVerifyTrust ((HWND) NULL, &policy, &trust);

	switch (status) {
	case ERROR_SUCCESS:
		*out_sig = FS_TRUST_SIG_VALID;
		answered = TRUE;
		break;

	case TRUST_E_NOSIGNATURE:
	case TRUST_E_SUBJECT_FORM_UNKNOWN:
		*out_sig = FS_TRUST_SIG_UNSIGNED;
		answered = TRUE;
		break;

	case TRUST_E_BAD_DIGEST:
	case TRUST_E_EXPLICIT_DISTRUST:
	case TRUST_E_SUBJECT_NOT_TRUSTED:
	case CERT_E_EXPIRED:
	case CERT_E_REVOKED:
	case CERT_E_UNTRUSTEDROOT:
	case CERT_E_CHAINING:
	case CERT_E_WRONG_USAGE:
		/* A signature exists and does not stand: bad digest means
		 * somebody edited the bytes under the signature, which is
		 * exactly the change this engine exists to notice. */
		*out_sig = FS_TRUST_SIG_INVALID;
		answered = TRUE;
		break;

	default:
		/* File vanished, access denied, anything unexpected: the
		 * platform failed to answer, so it answers FALSE and the
		 * caller keeps FS_TRUST_SIG_UNKNOWN rather than a guess. */
		break;
	}

	if (answered &&
	    (*out_sig == FS_TRUST_SIG_VALID ||
	     *out_sig == FS_TRUST_SIG_INVALID))
		*out_publisher = signer_publisher (path);

	g_free (wide);
	return answered;
}
