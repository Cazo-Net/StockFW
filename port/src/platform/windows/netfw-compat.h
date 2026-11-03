/*---[ netfw-compat.h ]-------------------------------------------------
 * What MinGW-w64's netfw.h needs beside it.
 *
 * 1. The CLSID / IID symbols only get storage with INITGUID defined,
 *    and even then taking their address segfaulted in testing.  The
 *    values are documented, so they are defined locally here instead
 *    of relying on the header's.
 *
 * 2. The vtable slots StockFW calls are pinned to their documented
 *    positions (netfw.idl in the Windows SDK) at compile time.  A
 *    netfw.h whose layout disagreed would make a COM call land on the
 *    wrong method and crash or corrupt; with these checks the build
 *    stops instead.  Position n is n pointers into the vtable: 0-2 are
 *    IUnknown, 3-6 IDispatch, the interface's own methods follow in
 *    declaration order.
 *
 * An earlier version of this header also carried a "corrected"
 * INetFwRules vtable with Add(INetFwRule **), Remove(LONG) and
 * Item(LONG, ...).  Those are not INetFwRules' signatures: Microsoft
 * documents Add(INetFwRule *), Remove(BSTR name) and Item(BSTR name,
 * INetFwRule **), which is what MinGW declares.  It was never used and
 * is gone (1.0.7 Round 3).
 *--------------------------------------------------------------------*/
#ifndef FS_NETFW_COMPAT_H
#define FS_NETFW_COMPAT_H

#include <stddef.h>
#include <netfw.h>

/* HNetCfg.FwPolicy2 */
static const GUID FS_CLSID_NetFwPolicy2 =
	{ 0xe2b3c97f, 0x6ae1, 0x41ac,
	  { 0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd } };

static const GUID FS_IID_INetFwPolicy2 =
	{ 0x98325047, 0xc671, 0x4174,
	  { 0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86 } };

/* HNetCfg.FWRule */
static const GUID FS_CLSID_NetFwRule =
	{ 0x2c5bc43e, 0x3369, 0x4c33,
	  { 0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4 } };

static const GUID FS_IID_INetFwRule =
	{ 0xaf230d27, 0xbaba, 0x4e42,
	  { 0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2 } };

/* Windows 8 and later: app packages, users, machines, IPsec flags. */
static const GUID FS_IID_INetFwRule3 =
	{ 0xb21563ff, 0xd696, 0x4222,
	  { 0xab, 0x46, 0x4e, 0x89, 0xb7, 0x3a, 0xb3, 0x4a } };

static const GUID FS_IID_IEnumVARIANT =
	{ 0x00020404, 0x0000, 0x0000,
	  { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

/* NET_FW_IP_PROTOCOL_ANY: a rule's protocol when none is set.  (The
 * IANA numbers are used for single protocols; 256 is the wildcard,
 * not 255.) */
#define FS_NETFW_PROTO_TCP  6
#define FS_NETFW_PROTO_UDP  17
#define FS_NETFW_PROTO_ANY  256

/* INetFwRule::Profiles is typed NET_FW_PROFILE_TYPE2 in this header, so
 * the profile names have to use their v2 spelling. */
#define FS_NETFW_PROFILE_ALL (NET_FW_PROFILE2_DOMAIN | \
			      NET_FW_PROFILE2_PRIVATE | \
			      NET_FW_PROFILE2_PUBLIC)

#define FS_NETFW_SLOT(vtbl, member, n) \
	_Static_assert (offsetof (vtbl, member) == (n) * sizeof (void *), \
	                #vtbl "." #member " is not at its documented slot " #n)

FS_NETFW_SLOT (INetFwPolicy2Vtbl, get_CurrentProfileTypes, 7);
FS_NETFW_SLOT (INetFwPolicy2Vtbl, get_FirewallEnabled, 8);
FS_NETFW_SLOT (INetFwPolicy2Vtbl, put_FirewallEnabled, 9);
FS_NETFW_SLOT (INetFwPolicy2Vtbl, get_ExcludedInterfaces, 10);
FS_NETFW_SLOT (INetFwPolicy2Vtbl, get_Rules, 18);
FS_NETFW_SLOT (INetFwPolicy2Vtbl, get_LocalPolicyModifyState, 28);

FS_NETFW_SLOT (INetFwRulesVtbl, get_Count, 7);
FS_NETFW_SLOT (INetFwRulesVtbl, Add, 8);
FS_NETFW_SLOT (INetFwRulesVtbl, Remove, 9);
FS_NETFW_SLOT (INetFwRulesVtbl, Item, 10);
FS_NETFW_SLOT (INetFwRulesVtbl, get__NewEnum, 11);

FS_NETFW_SLOT (INetFwRuleVtbl, get_Name, 7);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Name, 8);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Description, 9);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Description, 10);
FS_NETFW_SLOT (INetFwRuleVtbl, get_ApplicationName, 11);
FS_NETFW_SLOT (INetFwRuleVtbl, get_ServiceName, 13);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Protocol, 15);
FS_NETFW_SLOT (INetFwRuleVtbl, get_LocalPorts, 17);
FS_NETFW_SLOT (INetFwRuleVtbl, get_RemotePorts, 19);
FS_NETFW_SLOT (INetFwRuleVtbl, get_LocalAddresses, 21);
FS_NETFW_SLOT (INetFwRuleVtbl, get_RemoteAddresses, 23);
FS_NETFW_SLOT (INetFwRuleVtbl, put_RemoteAddresses, 24);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Direction, 27);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Direction, 28);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Interfaces, 29);
FS_NETFW_SLOT (INetFwRuleVtbl, get_InterfaceTypes, 31);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Enabled, 33);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Enabled, 34);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Grouping, 35);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Grouping, 36);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Profiles, 37);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Profiles, 38);
FS_NETFW_SLOT (INetFwRuleVtbl, get_Action, 41);
FS_NETFW_SLOT (INetFwRuleVtbl, put_Action, 42);

/* INetFwRule3 : INetFwRule2 (EdgeTraversalOptions, 43-44) : INetFwRule */
FS_NETFW_SLOT (INetFwRule3Vtbl, get_LocalAppPackageId, 45);
FS_NETFW_SLOT (INetFwRule3Vtbl, get_LocalUserOwner, 47);
FS_NETFW_SLOT (INetFwRule3Vtbl, get_LocalUserAuthorizedList, 49);
FS_NETFW_SLOT (INetFwRule3Vtbl, get_RemoteUserAuthorizedList, 51);
FS_NETFW_SLOT (INetFwRule3Vtbl, get_RemoteMachineAuthorizedList, 53);
FS_NETFW_SLOT (INetFwRule3Vtbl, get_SecureFlags, 55);

FS_NETFW_SLOT (IEnumVARIANTVtbl, Next, 3);

#undef FS_NETFW_SLOT

#endif /* FS_NETFW_COMPAT_H */
