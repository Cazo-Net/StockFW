/*---[ netfw-compat.h ]-------------------------------------------------
 * Work around bugs in MinGW-w64's netfw.h.
 *
 * Two separate problems, both hit while building the Windows backend:
 *
 * 1. INetFwRules is declared with the method signatures of
 *    INetFwAuthorizedApplications:
 *
 *      Add(INetFwRule *)          real API: Add(INetFwRule **)
 *      Remove(BSTR name)          real API: Remove(LONG index)
 *      Item(BSTR, INetFwRule **)  real API: Item(LONG index, INetFwRule **)
 *
 *    Those are different calling conventions, so calling them through
 *    the generated vtable corrupts the stack.  The real signatures are
 *    redeclared below.
 *
 * 2. The CLSID_NetFwPolicy2 / IID_INetFwPolicy2 symbols only get
 *    storage with INITGUID defined, and even then taking their address
 *    segfaulted in testing.  The values are documented, so they are
 *    defined locally here instead of relying on the header's.
 *
 * The header also omits NET_FW_RULE_PROTOCOL_*, which
 * INetFwRule::put_Protocol() needs; those are the IANA IP protocol
 * numbers, with 255 as the wildcard.
 *--------------------------------------------------------------------*/
#ifndef FS_NETFW_COMPAT_H
#define FS_NETFW_COMPAT_H

#include <netfw.h>

/* Documented values for HNetCfg.FwPolicy2. */
static const GUID FS_CLSID_NetFwPolicy2 =
	{ 0xe2b3c97f, 0x6ae1, 0x41ac,
	  { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd } };

static const GUID FS_IID_INetFwPolicy2 =
	{ 0x98325047, 0xc671, 0x4174,
	  { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 } };

/* IANA protocol numbers, as INetFwRule::put_Protocol expects. */
#define FS_NETFW_PROTO_TCP  6
#define FS_NETFW_PROTO_UDP  17
#define FS_NETFW_PROTO_ANY  255

/* INetFwRule::Profiles is typed NET_FW_PROFILE_TYPE2 in this header, so
 * the profile names have to use their v2 spelling. */
#define FS_NETFW_PROFILE_ALL (NET_FW_PROFILE2_DOMAIN | \
			      NET_FW_PROFILE2_PRIVATE | \
			      NET_FW_PROFILE2_PUBLIC)

/* Correct INetFwRules vtable: IUnknown + IDispatch, then the real
 * method signatures. */
typedef struct FsINetFwRulesVtbl
{
	/* IUnknown */
	HRESULT (STDMETHODCALLTYPE *QueryInterface) (void *self, REFIID riid,
	                                             void **ppvObject);
	ULONG   (STDMETHODCALLTYPE *AddRef)        (void *self);
	ULONG   (STDMETHODCALLTYPE *Release)       (void *self);

	/* IDispatch */
	HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount) (void *self, UINT *count);
	HRESULT (STDMETHODCALLTYPE *GetTypeInfo)      (void *self, UINT tab,
	                                              LCID lcid,
	                                              ITypeInfo **info);
	HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)    (void *self, REFIID riid,
	                                              LPOLESTR *names,
	                                              UINT count, LCID lcid,
	                                              DISPID *ids);
	HRESULT (STDMETHODCALLTYPE *Invoke)           (void *self, DISPID id,
	                                              REFIID riid, LCID lcid,
	                                              WORD flags,
	                                              DISPPARAMS *params,
	                                              VARIANT *result,
	                                              EXCEPINFO *info);

	/* INetFwRules, correctly this time. */
	HRESULT (STDMETHODCALLTYPE *get_Count) (void *self, LONG *count);
	HRESULT (STDMETHODCALLTYPE *Add)      (void *self, INetFwRule **rule);
	HRESULT (STDMETHODCALLTYPE *Remove)   (void *self, LONG index);
	HRESULT (STDMETHODCALLTYPE *Item)     (void *self, LONG index,
	                                       INetFwRule **rule);
	HRESULT (STDMETHODCALLTYPE *get__NewEnum) (void *self, IUnknown **e);
} FsINetFwRulesVtbl;

typedef struct FsINetFwRules
{
	const FsINetFwRulesVtbl *lpVtbl;
} FsINetFwRules;

/* Cast the INetFwRules we get from get_Rules() to the corrected
 * interface. */
static inline FsINetFwRules *
fs_netfw_rules (INetFwRules *rules)
{
	return (FsINetFwRules *) rules;
}

#endif /* FS_NETFW_COMPAT_H */