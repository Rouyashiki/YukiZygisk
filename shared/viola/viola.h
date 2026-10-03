/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Bounded shared Viola signature and manifest verification
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_H
#define YUKIZYGISK_VIOLA_H
#include "viola_port.h"
#ifdef __cplusplus
extern "C" {
#endif
#define VIOLA_MANIFEST_MAX 8192u
#define VIOLA_SIGNATURE_MAX 4096u
#define VIOLA_ENTRY_MAX 64u
#define VIOLA_HEADER_SIZE 128u
#define VIOLA_ENTRY_SIZE 88u
#define VIOLA_DIGEST_SIZE 64u
#define VIOLA_ID_SIZE 32u
#define VIOLA_FORMAT_VERSION 1u
#define VIOLA_POLICY_VERSION 1u
#define VIOLA_PROTOCOL_VERSION 2u
#define VIOLA_PROFILE_OFFICIAL 1u
#define VIOLA_PROFILE_DEV 2u
#define VIOLA_ABI_ARM64 1u
#define VIOLA_ABI_ARM32 2u
enum viola_payload_role {
	VIOLA_ROLE_VIOLA = 1,
	VIOLA_ROLE_KO = 2,
	VIOLA_ROLE_DAEMON = 3,
	VIOLA_ROLE_CTL = 4,
	VIOLA_ROLE_LOADER = 5,
	VIOLA_ROLE_CORE = 6,
	VIOLA_ROLE_NATIVE = 7
};
enum viola_result {
	VIOLA_OK = 0,
	VIOLA_ERR_ARGUMENT = 1,
	VIOLA_ERR_FORMAT = 2,
	VIOLA_ERR_SIGNATURE = 3,
	VIOLA_ERR_IDENTITY = 4,
	VIOLA_ERR_PAYLOAD = 5,
	VIOLA_ERR_NOT_FOUND = 6
};
/* Views borrow immutable input storage. Keep the manifest alive for every use. */
struct viola_manifest_view {
	const uint8_t *data;
	size_t size;
	const uint8_t *release_id;
	const uint8_t *trust_id;
	uint64_t version_code;
	uint32_t profile;
	uint32_t policy;
	uint32_t protocol;
	uint16_t entry_count;
};
struct viola_entry {
	uint16_t role;
	uint16_t abi;
	uint32_t kmi;
	uint32_t flags;
	uint64_t size;
	const uint8_t *sha512;
};
int viola_manifest_parse(const void *data, size_t size, struct viola_manifest_view *out);
/* verify authenticates the signature AND checks this build's identity. */
int viola_manifest_verify(const void *data, size_t size, const void *signature,
			  size_t signature_size, struct viola_manifest_view *out);
int viola_manifest_find(const struct viola_manifest_view *view, uint16_t role, uint16_t abi,
			uint32_t kmi, struct viola_entry *out);
int viola_check_identity(const struct viola_manifest_view *view);
int viola_check_payload(const struct viola_entry *entry, const void *data, size_t size);
int viola_hash(uint8_t out[VIOLA_DIGEST_SIZE], const void *data, size_t size);
int viola_entry_at(const struct viola_manifest_view *view, unsigned index, struct viola_entry *out);
const char *viola_role_name(uint16_t role);
const char *viola_kmi_name(uint32_t kmi);
int viola_kmi_id(const char *name);
int viola_entry_path(const struct viola_entry *entry, char *out, size_t capacity);
const char *viola_result_string(int result);
#ifdef __cplusplus
}
#endif
#endif
