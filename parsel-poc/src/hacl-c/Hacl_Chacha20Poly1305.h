/* MIT License
 *
 * Copyright (c) 2016-2017 INRIA and Microsoft Corporation
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

#include "kremlib.h"
#ifndef __Hacl_Chacha20Poly1305_H
#define __Hacl_Chacha20Poly1305_H


#include "Hacl_Policies.h"
#include "Hacl_Chacha20.h"
#include "AEAD_Poly1305_64.h"

extern Prims_int Hacl_Chacha20Poly1305_noncelen;

extern Prims_int Hacl_Chacha20Poly1305_keylen;

extern Prims_int Hacl_Chacha20Poly1305_maclen;

typedef Hacl_Impl_Poly1305_64_State_poly1305_state Hacl_Chacha20Poly1305_state;

typedef void *Hacl_Chacha20Poly1305_log_t;

void Hacl_Chacha20Poly1305_encode_length(uint8_t *lb, uint32_t aad_len, uint32_t mlen);

uint32_t
Hacl_Chacha20Poly1305_aead_encrypt_(
  uint8_t *c,
  uint8_t *mac,
  uint8_t *m,
  uint32_t mlen,
  uint8_t *aad1,
  uint32_t aadlen,
  uint8_t *k1,
  uint8_t *n1
);

uint32_t
Hacl_Chacha20Poly1305_aead_encrypt(
  uint8_t *c,
  uint8_t *mac,
  uint8_t *m,
  uint32_t mlen,
  uint8_t *aad1,
  uint32_t aadlen,
  uint8_t *k1,
  uint8_t *n1
);

uint32_t
Hacl_Chacha20Poly1305_aead_decrypt(
  uint8_t *m,
  uint8_t *c,
  uint32_t mlen,
  uint8_t *mac,
  uint8_t *aad1,
  uint32_t aadlen,
  uint8_t *k1,
  uint8_t *n1
);
#endif
