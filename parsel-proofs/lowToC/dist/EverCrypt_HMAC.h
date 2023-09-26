/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef __EverCrypt_HMAC_H
#define __EverCrypt_HMAC_H
#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"


#include "Hacl_Spec.h"
#include "/home/seoyeon/workspace/sel4-tutorials-manifest/dynamic-3/everest/hacl-star/lib/c/evercrypt_targetconfig.h"
#include "/home/seoyeon/workspace/sel4-tutorials-manifest/dynamic-3/everest/hacl-star/lib/c/libintvector.h"
typedef uint8_t Lib_IntTypes_uint1;
#include "vspace/vspace.h"
extern void
EverCrypt_HMAC_compute_sha1(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

extern void
EverCrypt_HMAC_compute_sha2_256(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

extern void
EverCrypt_HMAC_compute_sha2_384(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

extern void
EverCrypt_HMAC_compute_sha2_512(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

extern void
EverCrypt_HMAC_compute_blake2s(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

extern void
EverCrypt_HMAC_compute_blake2b(
  Lib_IntTypes_uint1 *uu___,
  Lib_IntTypes_uint1 *x0,
  uint32_t x1,
  Lib_IntTypes_uint1 *x2,
  uint32_t x3
);

bool EverCrypt_HMAC_is_supported_alg(Spec_Hash_Definitions_hash_alg uu___);

typedef Spec_Hash_Definitions_hash_alg EverCrypt_HMAC_supported_alg;

extern void
EverCrypt_HMAC_compute(
  Spec_Hash_Definitions_hash_alg a,
  Lib_IntTypes_uint1 *x0,
  Lib_IntTypes_uint1 *x1,
  uint32_t x2,
  Lib_IntTypes_uint1 *x3,
  uint32_t x4
);


#define __EverCrypt_HMAC_H_DEFINED
#endif
