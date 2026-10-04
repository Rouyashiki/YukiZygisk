/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Bounded OpenPGP and core manifest verifier
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "viola.h"
#include "vendor/monocypher-ed25519.h"
#include <viola_build.h>

typedef struct {
	const uint8_t *p;
	size_t n;
} Cursor;
typedef struct {
	const uint8_t *hashed;
	size_t hashed_size;
	const uint8_t *hash_prefix;
	const uint8_t *fingerprint;
	const uint8_t *keyid;
	unsigned seen_creation;
	uint8_t raw[64];
} Signature;

static int take(Cursor *c, size_t n, const uint8_t **p)
{
	if (n > c->n)
		return 0;
	*p = c->p;
	c->p += n;
	c->n -= n;
	return 1;
}

static unsigned be16(const uint8_t *p)
{
	return ((unsigned)p[0] << 8) | p[1];
}

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* New-format packet lengths and signature subpacket lengths differ for
 * 224..254: these are partial packet lengths but two-octet subpacket lengths.
 */
static int length(Cursor *c, size_t *n, int subpacket)
{
	const uint8_t *p;
	if (!take(c, 1, &p))
		return 0;
	unsigned lead = p[0];
	if (lead < 192)
		*n = lead;
	else if (lead < 255 && (subpacket || lead < 224)) {
		if (!take(c, 1, &p))
			return 0;
		*n = ((lead - 192) << 8) + p[0] + 192;
	} else if (lead == 255) {
		if (!take(c, 4, &p))
			return 0;
		*n = be32(p);
	} else
		return 0;
	return 1;
}

static int signature_packet(Cursor *outer, Cursor *body)
{
	const uint8_t *p;
	size_t n;
	if (!take(outer, 1, &p) || !(p[0] & 128))
		return 0;
	unsigned header = p[0];
	if (header & 64) {
		if ((header & 63) != 2 || !length(outer, &n, 0))
			return 0;
	} else {
		unsigned ltype = header & 3;
		if (((header >> 2) & 15) != 2 || ltype == 3)
			return 0;
		unsigned bytes = 1u << ltype;
		if (!take(outer, bytes, &p))
			return 0;
		n = bytes == 1 ? p[0] : bytes == 2 ? be16(p) : be32(p);
	}
	if (!take(outer, n, &p) || outer->n)
		return 0;
	body->p = p;
	body->n = n;
	return 1;
}

static int subpackets(Cursor sub, int hashed, Signature *sig)
{
	while (sub.n) {
		size_t n;
		const uint8_t *p;
		if (!length(&sub, &n, 1) || !n || !take(&sub, n, &p))
			return 0;
		unsigned type = p[0] & 127;
		if (type == 2 && hashed && n == 5 && !sig->seen_creation) {
			sig->seen_creation = 1;
		} else if (type == 33 && hashed && n == 22 && p[1] == 4 && !sig->fingerprint) {
			sig->fingerprint = p + 2;
		} else if (type == 16 && !hashed && n == 9 && !sig->keyid) {
			sig->keyid = p + 1;
		} else if (type == 20 && hashed && !(p[0] & 128) && n >= 9 &&
			   n - 9 == (size_t)be16(p + 5) + be16(p + 7)) {
			/* GnuPG 2.5.18 adds a noncritical "manu" notation by default.
			 * No notation value is used for trust or release policy. Unknown
			 * critical notation semantics must still fail closed. */
		} else {
			/* No unimplemented signed semantics, duplicate fields, duplicate fields,
			 * expiration or unsupported critical fields are silently ignored. */
			return 0;
		}
	}
	return 1;
}

static int legacy_mpi(Cursor *body, uint8_t out[32])
{
	const uint8_t *p;
	if (!take(body, 2, &p))
		return 0;
	unsigned bits = be16(p);
	size_t n = (bits + 7u) / 8u;
	if (!bits || bits > 256 || !take(body, n, &p))
		return 0;
	unsigned topbits = 0;
	for (unsigned v = p[0]; v; v >>= 1)
		topbits++;
	if (!topbits || (n - 1) * 8 + topbits != bits)
		return 0;
	/* RFC 9580 5.2.3.3.1: MPI bytes represent native octet strings.
	 * MPI encoding strips leading zero octets. Restore them on the LEFT,
	 * matching GnuPG g10/pkglue.c. Do NOT reverse R or S.
	 */
	memset(out, 0, 32);
	memcpy(out + 32 - n, p, n);
	return 1;
}

static int parse_signature(const uint8_t *data, size_t size, Signature *sig)
{
	Cursor outer = {data, size}, body, sub;
	const uint8_t *p;
	if (!signature_packet(&outer, &body))
		return 0;
	sig->hashed = body.p;
	if (!take(&body, 6, &p) || p[0] != 4 || p[1] != 0 || p[2] != 22 || p[3] != 10)
		return 0;
	size_t n = be16(p + 4);
	if (!take(&body, n, &p))
		return 0;
	sig->hashed_size = 6 + n;
	sub.p = p;
	sub.n = n;
	if (!subpackets(sub, 1, sig) || !sig->seen_creation)
		return 0;
	if (!take(&body, 2, &p))
		return 0;
	n = be16(p);
	if (!take(&body, n, &p))
		return 0;
	sub.p = p;
	sub.n = n;
	if (!subpackets(sub, 0, sig))
		return 0;
	if (sig->fingerprint && sig->keyid && memcmp(sig->fingerprint + 12, sig->keyid, 8))
		return 0;
	if (!take(&body, 2, &sig->hash_prefix) || !legacy_mpi(&body, sig->raw) ||
	    !legacy_mpi(&body, sig->raw + 32) || body.n)
		return 0;
	return 1;
}

static uint16_t le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t le64(const uint8_t *p)
{
	return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static int zeroes(const uint8_t *p, size_t n)
{
	uint8_t bits = 0;
	while (n--)
		bits |= *p++;
	return bits == 0;
}

const char *viola_kmi_name(uint32_t kmi)
{
	static const char *const names[] = {"none",	      "android12-5.10", "android13-5.10",
					    "android13-5.15", "android14-5.15", "android14-6.1",
					    "android15-6.6",  "android16-6.12", "android17-6.18"};
	return kmi < sizeof(names) / sizeof(names[0]) ? names[kmi] : NULL;
}

int viola_kmi_id(const char *name)
{
	unsigned i;
	if (!name)
		return -1;
	for (i = 0; viola_kmi_name(i); ++i)
		if (!strcmp(name, viola_kmi_name(i)))
			return (int)i;
	return -1;
}

const char *viola_role_name(uint16_t role)
{
	static const char *const names[] = {NULL,  "viola",  "ko",   "daemon",
					    "ctl", "loader", "core", "native"};
	return role < sizeof(names) / sizeof(names[0]) ? names[role] : NULL;
}

static int valid_entry(const struct viola_entry *e)
{
	if (!viola_role_name(e->role) || e->flags || !e->size ||
	    (e->abi != VIOLA_ABI_ARM64 && e->abi != VIOLA_ABI_ARM32))
		return 0;
	if (e->role == VIOLA_ROLE_KO)
		return e->abi == VIOLA_ABI_ARM64 && e->kmi >= 1 && viola_kmi_name(e->kmi);
	if (e->kmi)
		return 0;
	return (e->role != VIOLA_ROLE_VIOLA && e->role != VIOLA_ROLE_CTL) ||
	       e->abi == VIOLA_ABI_ARM64;
}

int viola_entry_at(const struct viola_manifest_view *view, unsigned index, struct viola_entry *out)
{
	const uint8_t *p;
	size_t offset;
	if (!view || !out || !view->data || index >= view->entry_count || index >= VIOLA_ENTRY_MAX)
		return VIOLA_ERR_ARGUMENT;
	offset = VIOLA_HEADER_SIZE + (size_t)index * VIOLA_ENTRY_SIZE;
	if (offset > view->size || view->size - offset < VIOLA_ENTRY_SIZE)
		return VIOLA_ERR_FORMAT;
	p = view->data + offset;
	memset(out, 0, sizeof(*out));
	out->role = le16(p);
	out->abi = le16(p + 2);
	out->kmi = le32(p + 4);
	out->flags = le32(p + 8);
	out->size = le64(p + 16);
	out->sha512 = p + 24;
	return zeroes(p + 12, 4) && valid_entry(out) ? VIOLA_OK : VIOLA_ERR_FORMAT;
}

int viola_manifest_parse(const void *data, size_t size, struct viola_manifest_view *out)
{
	static const uint8_t magic[8] = {'V', 'I', 'O', 'L', 'A', 0, 1, 0};
	static const uint8_t project[16] = "YukiZygisk";
	const uint8_t *p = data;
	struct viola_manifest_view view;
	struct viola_entry previous = {0}, entry;
	uint32_t seen = 0;
	unsigned i;
	if (!out)
		return VIOLA_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	if (!p || size < VIOLA_HEADER_SIZE || size > VIOLA_MANIFEST_MAX)
		return VIOLA_ERR_FORMAT;
	if (memcmp(p, magic, sizeof(magic)) || le16(p + 8) != VIOLA_FORMAT_VERSION ||
	    le16(p + 10) != VIOLA_HEADER_SIZE || le32(p + 12) != size || !le16(p + 16) ||
	    le16(p + 16) > VIOLA_ENTRY_MAX || le16(p + 18) != VIOLA_ENTRY_SIZE ||
	    size != VIOLA_HEADER_SIZE + (size_t)le16(p + 16) * VIOLA_ENTRY_SIZE ||
	    (le32(p + 20) != VIOLA_PROFILE_OFFICIAL && le32(p + 20) != VIOLA_PROFILE_DEV) ||
	    le32(p + 24) != VIOLA_POLICY_VERSION || le32(p + 28) != VIOLA_PROTOCOL_VERSION ||
	    zeroes(p + 32, 32) || zeroes(p + 64, 32) || !le64(p + 96) ||
	    memcmp(p + 104, project, sizeof(project)) || !zeroes(p + 120, 8))
		return VIOLA_ERR_FORMAT;
	memset(&view, 0, sizeof(view));
	view.data = p;
	view.size = size;
	view.entry_count = le16(p + 16);
	view.profile = le32(p + 20);
	view.policy = le32(p + 24);
	view.protocol = le32(p + 28);
	view.release_id = p + 32;
	view.trust_id = p + 64;
	view.version_code = le64(p + 96);
	for (i = 0; i < view.entry_count; ++i) {
		int result = viola_entry_at(&view, i, &entry);
		if (result)
			return result;
		if (i && (previous.role > entry.role ||
			  (previous.role == entry.role && previous.abi > entry.abi) ||
			  (previous.role == entry.role && previous.abi == entry.abi &&
			   previous.kmi >= entry.kmi)))
			return VIOLA_ERR_FORMAT;
		previous = entry;
		seen |= 1u << (entry.role * 2u + entry.abi);
	}
	/* Current packages contain both native ABIs and at least one supported KO.
	 * A valid publisher signature cannot turn a partial catalog into a package.
	 */
	for (i = VIOLA_ROLE_VIOLA; i <= VIOLA_ROLE_NATIVE; ++i) {
		if (!(seen & (1u << (i * 2u + VIOLA_ABI_ARM64))))
			return VIOLA_ERR_FORMAT;
		if (i != VIOLA_ROLE_VIOLA && i != VIOLA_ROLE_KO && i != VIOLA_ROLE_CTL &&
		    !(seen & (1u << (i * 2u + VIOLA_ABI_ARM32))))
			return VIOLA_ERR_FORMAT;
	}
	*out = view;
	return VIOLA_OK;
}

int viola_check_identity(const struct viola_manifest_view *view)
{
	static const uint8_t release_id[32] = VIOLA_RELEASE_ID_BYTES;
	static const uint8_t trust_id[32] = VIOLA_TRUST_ID_BYTES;
	if (!view || !view->release_id || !view->trust_id)
		return VIOLA_ERR_ARGUMENT;
	if (view->profile != VIOLA_PROFILE || view->policy != VIOLA_POLICY_VERSION ||
	    view->protocol != VIOLA_PROTOCOL_VERSION || view->version_code != VIOLA_VERSION_CODE ||
	    memcmp(view->release_id, release_id, sizeof(release_id)) ||
	    memcmp(view->trust_id, trust_id, sizeof(trust_id)))
		return VIOLA_ERR_IDENTITY;
	return VIOLA_OK;
}

int viola_manifest_verify(const void *data, size_t size, const void *signature,
			  size_t signature_size, struct viola_manifest_view *out)
{
	static const uint8_t public_key[32] = VIOLA_PUBLIC_KEY_BYTES;
	static const uint8_t fingerprint[20] = VIOLA_SIGNER_FINGERPRINT_BYTES;
	struct viola_manifest_view view;
	Signature sig = {0};
	crypto_sha512_ctx ctx;
	uint8_t digest[64], trailer[6];
	uint32_t n;
	int result;
	if (!out)
		return VIOLA_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	result = viola_manifest_parse(data, size, &view);
	if (result)
		return result;
	result = viola_check_identity(&view);
	if (result)
		return result;
	if (!signature || !signature_size || signature_size > VIOLA_SIGNATURE_MAX ||
	    !parse_signature(signature, signature_size, &sig) || !sig.fingerprint ||
	    memcmp(sig.fingerprint, fingerprint, sizeof(fingerprint)))
		return VIOLA_ERR_SIGNATURE;
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, data, size);
	crypto_sha512_update(&ctx, sig.hashed, sig.hashed_size);
	n = (uint32_t)sig.hashed_size;
	trailer[0] = 4;
	trailer[1] = 255;
	trailer[2] = (uint8_t)(n >> 24);
	trailer[3] = (uint8_t)(n >> 16);
	trailer[4] = (uint8_t)(n >> 8);
	trailer[5] = (uint8_t)n;
	crypto_sha512_update(&ctx, trailer, sizeof(trailer));
	crypto_sha512_final(&ctx, digest);
	if (memcmp(digest, sig.hash_prefix, 2) ||
	    crypto_ed25519_check(sig.raw, public_key, digest, sizeof(digest)))
		return VIOLA_ERR_SIGNATURE;
	*out = view;
	return VIOLA_OK;
}

int viola_manifest_find(const struct viola_manifest_view *view, uint16_t role, uint16_t abi,
			uint32_t kmi, struct viola_entry *out)
{
	unsigned i;
	if (!view || !out)
		return VIOLA_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	for (i = 0; i < view->entry_count; ++i) {
		struct viola_entry e;
		int result = viola_entry_at(view, i, &e);
		if (result)
			return result;
		if (e.role == role && e.abi == abi && e.kmi == kmi) {
			*out = e;
			return VIOLA_OK;
		}
	}
	return VIOLA_ERR_NOT_FOUND;
}

int viola_hash(uint8_t out[VIOLA_DIGEST_SIZE], const void *data, size_t size)
{
	if (!out || (!data && size))
		return VIOLA_ERR_ARGUMENT;
	crypto_sha512(out, data, size);
	return VIOLA_OK;
}

int viola_check_payload(const struct viola_entry *entry, const void *data, size_t size)
{
	uint8_t digest[VIOLA_DIGEST_SIZE];
	if (!entry || !entry->sha512 || (!data && size))
		return VIOLA_ERR_ARGUMENT;
	if (entry->size != size)
		return VIOLA_ERR_PAYLOAD;
	viola_hash(digest, data, size);
	return crypto_verify64(digest, entry->sha512) ? VIOLA_ERR_PAYLOAD : VIOLA_OK;
}

int viola_entry_path(const struct viola_entry *entry, char *out, size_t capacity)
{
	const char *prefix = "", *name = NULL, *suffix = "";
	size_t a, b, c;
	if (!entry || !out || !valid_entry(entry))
		return VIOLA_ERR_ARGUMENT;
	switch (entry->role) {
	case VIOLA_ROLE_VIOLA:
		name = "bin/viola";
		break;
	case VIOLA_ROLE_KO:
		prefix = "lkm/";
		name = viola_kmi_name(entry->kmi);
		suffix = "_yukizygisk.ko";
		break;
	case VIOLA_ROLE_DAEMON:
		name = entry->abi == VIOLA_ABI_ARM64 ? "bin/zygiskd64" : "bin/zygiskd32";
		break;
	case VIOLA_ROLE_CTL:
		name = "bin/yzctl";
		break;
	case VIOLA_ROLE_LOADER:
		name = "libyukilinker.so";
		break;
	case VIOLA_ROLE_CORE:
		name = "libzygisk.so";
		break;
	case VIOLA_ROLE_NATIVE:
		name = "libyukizncore.so";
		break;
	default:
		return VIOLA_ERR_ARGUMENT;
	}
	if (entry->role >= VIOLA_ROLE_LOADER)
		prefix = entry->abi == VIOLA_ABI_ARM64 ? "lib64/" : "lib/";
	a = strlen(prefix);
	b = strlen(name);
	c = strlen(suffix);
	if (a + b + c + 1 > capacity)
		return VIOLA_ERR_ARGUMENT;
	memcpy(out, prefix, a);
	memcpy(out + a, name, b);
	memcpy(out + a + b, suffix, c + 1);
	return VIOLA_OK;
}

const char *viola_result_string(int result)
{
	switch (result) {
	case VIOLA_OK:
		return "ok";
	case VIOLA_ERR_ARGUMENT:
		return "invalid argument";
	case VIOLA_ERR_FORMAT:
		return "invalid manifest";
	case VIOLA_ERR_SIGNATURE:
		return "invalid signature";
	case VIOLA_ERR_IDENTITY:
		return "different build identity";
	case VIOLA_ERR_PAYLOAD:
		return "different payload bytes";
	case VIOLA_ERR_NOT_FOUND:
		return "missing core role";
	default:
		return "unknown verification error";
	}
}
