/*---[ fs-mesh.h ]-------------------------------------------------------
 * P2P Encrypted Local Fleet Mesh & TPM Attestation
 * Part of StockFW Phase v3.0 (The Guinness Standard)
 *
 * Synchronizes threat intelligence and adaptive isolation rules peer-to-peer
 * over encrypted WireGuard tunnels without centralized cloud controllers.
 *--------------------------------------------------------------------*/
#ifndef FS_MESH_H
#define FS_MESH_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
	gchar *node_id;
	gchar *endpoint_ip;
	guint  port;
	gboolean tpm_verified;
} FsMeshNode;

typedef struct
{
	gchar *source_node_id;
	gchar *ruleset_hash;
	guint64 timestamp;
	guint8 *payload;
	gsize payload_len;
	gchar *signature;
} FsMeshSyncPacket;

/* Node allocation and management */
FsMeshNode *fs_mesh_node_new (const gchar *node_id, const gchar *endpoint_ip, guint port, gboolean tpm_verified);
void fs_mesh_node_free (FsMeshNode *node);

/* Generate WireGuard peer configuration snippet for local sovereign mesh */
gchar *fs_mesh_generate_peer_config (const FsMeshNode *node, const gchar *preshared_key);

/* Generate TPM 2.0 policy attestation statement */
gchar *fs_mesh_generate_tpm_attestation (const gchar *policy_hash);

/* Mesh synchronization packet management and stubs */
FsMeshSyncPacket *fs_mesh_sync_packet_new (const gchar *source_node_id,
                                           const gchar *ruleset_hash,
                                           const guint8 *payload,
                                           gsize payload_len,
                                           const gchar *signature);
void fs_mesh_sync_packet_free (FsMeshSyncPacket *packet);

/* Serialize sync packet to JSON string */
gchar *fs_mesh_serialize_sync_packet (const FsMeshSyncPacket *packet);

/* Parse sync packet from JSON string */
FsMeshSyncPacket *fs_mesh_parse_sync_packet (const gchar *json_str, GError **error);

/* Verify sync packet cryptographic signature and TPM attestation status */
gboolean fs_mesh_verify_sync_packet (const FsMeshSyncPacket *packet, const gchar *expected_tpm_policy_hash);

/* Broadcast or transmit sync packet across encrypted mesh node tunnel stub */
gboolean fs_mesh_sync_broadcast (const FsMeshNode *node, const FsMeshSyncPacket *packet);

G_END_DECLS

#endif /* FS_MESH_H */
