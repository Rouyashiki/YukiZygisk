/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Build identity note shared by Viola protected images
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef YUKIZYGISK_VIOLA_IDENTITY_H
#define YUKIZYGISK_VIOLA_IDENTITY_H
#include "viola.h"
#include <viola_build.h>
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if __has_attribute(retain) && !defined(__KERNEL__)
#define VIOLA_NOTE_RETAIN __attribute__((retain))
#else
#define VIOLA_NOTE_RETAIN
#endif
/* ELF note descriptor: little-endian, 104 bytes, no native padding.
 * Kernel linkers must KEEP(*(.note.viola)); userspace uses SHF_GNU_RETAIN.
 */
struct viola_identity_note {
	uint32_t namesz, descsz, type;
	char name[8];
	struct {
		uint8_t magic[8];
		uint32_t profile, policy, protocol, role, abi, kmi;
		uint64_t version_code;
		uint8_t release_id[32], trust_id[32];
	} __attribute__((packed)) identity;
} __attribute__((packed));
#define VIOLA_EMBED_IDENTITY(role_value, abi_value, kmi_value)                                     \
	static const struct viola_identity_note viola_image_identity                               \
	    __attribute__((section(".note.viola"), used, aligned(4))) VIOLA_NOTE_RETAIN = {        \
		6,                                                                                 \
		104,                                                                               \
		1,                                                                                 \
		{'V', 'I', 'O', 'L', 'A', 0, 0, 0},                                                \
		{{'V', 'I', 'O', 'L', 'A', 'I', 'D', '1'},                                         \
		 VIOLA_PROFILE,                                                                    \
		 VIOLA_POLICY_VERSION,                                                             \
		 VIOLA_PROTOCOL_VERSION,                                                           \
		 (role_value),                                                                     \
		 (abi_value),                                                                      \
		 (kmi_value),                                                                      \
		 VIOLA_VERSION_CODE,                                                               \
		 VIOLA_RELEASE_ID_BYTES,                                                           \
		 VIOLA_TRUST_ID_BYTES}}
#endif
