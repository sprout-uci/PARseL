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


#ifndef __internal_Hacl_Lib_H
#define __internal_Hacl_Lib_H
#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"



#include "/home/seoyeon/workspace/sel4-tutorials-manifest/dynamic-3/everest/hacl-star/lib/c/evercrypt_targetconfig.h"
#include "/home/seoyeon/workspace/sel4-tutorials-manifest/dynamic-3/everest/hacl-star/lib/c/libintvector.h"
#include "vspace/vspace.h"
#define Lib_IntTypes_U1 0
#define Lib_IntTypes_U8 1
#define Lib_IntTypes_U16 2
#define Lib_IntTypes_U32 3
#define Lib_IntTypes_U64 4
#define Lib_IntTypes_U128 5
#define Lib_IntTypes_S8 6
#define Lib_IntTypes_S16 7
#define Lib_IntTypes_S32 8
#define Lib_IntTypes_S64 9
#define Lib_IntTypes_S128 10

typedef uint8_t Lib_IntTypes_inttype;

#define Lib_IntTypes_SEC 0
#define Lib_IntTypes_PUB 1

typedef uint8_t Lib_IntTypes_secrecy_level;

extern void
*Lib_IntTypes_mk_int(Lib_IntTypes_inttype t, Lib_IntTypes_secrecy_level l, Prims_int n);


#define __internal_Hacl_Lib_H_DEFINED
#endif
