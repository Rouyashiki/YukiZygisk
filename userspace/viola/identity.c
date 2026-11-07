/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Embed the protected image's build identity.
 *
 * License: Apache-2.0
 *
 * Author: Rouyashiki Developers
 */
#include "viola_identity.h"
VIOLA_EMBED_IDENTITY(VIOLA_IMAGE_ROLE, VIOLA_IMAGE_ABI, 0);
