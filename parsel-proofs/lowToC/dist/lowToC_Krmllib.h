/* 
  This file was generated by KaRaMeL <https://github.com/FStarLang/karamel>
  KaRaMeL invocation: /home/seoyeon/workspace/sel4-tutorials-manifest/dynamic-3/everest/karamel/krml obj/FStar_Pervasives_Native.krml obj/FStar_Pervasives.krml obj/FStar_Range.krml obj/FStar_Tactics_Common.krml obj/FStar_VConfig.krml obj/FStar_Reflection_Types.krml obj/FStar_Tactics_Types.krml obj/FStar_Tactics_Result.krml obj/FStar_Squash.krml obj/FStar_Classical.krml obj/FStar_Preorder.krml obj/FStar_Calc.krml obj/FStar_Monotonic_Pure.krml obj/FStar_Tactics_Effect.krml obj/FStar_Reflection_Data.krml obj/FStar_Tactics_Builtins.krml obj/FStar_FunctionalExtensionality.krml obj/FStar_Set.krml obj/FStar_Map.krml obj/FStar_Mul.krml obj/Vale_Lib_Set.krml obj/Vale_Lib_Meta.krml obj/Vale_Def_Words_s.krml obj/Vale_Def_Words_Two_s.krml obj/FStar_StrongExcludedMiddle.krml obj/FStar_Classical_Sugar.krml obj/FStar_List_Tot_Base.krml obj/FStar_List_Tot_Properties.krml obj/FStar_List_Tot.krml obj/FStar_Seq_Base.krml obj/FStar_Seq_Properties.krml obj/FStar_Seq.krml obj/Vale_Lib_Seqs_s.krml obj/FStar_Math_Lib.krml obj/FStar_Math_Lemmas.krml obj/FStar_BitVector.krml obj/FStar_UInt.krml obj/FStar_UInt32.krml obj/FStar_UInt8.krml obj/Vale_Def_Words_Four_s.krml obj/Vale_Def_Words_Seq_s.krml obj/Vale_Def_Opaque_s.krml obj/Vale_Def_Types_s.krml obj/Vale_Def_Words_Two.krml obj/FStar_Exn.krml obj/FStar_Monotonic_Witnessed.krml obj/FStar_Ghost.krml obj/FStar_ErasedLogic.krml obj/FStar_PropositionalExtensionality.krml obj/FStar_PredicateExtensionality.krml obj/FStar_TSet.krml obj/FStar_Monotonic_Heap.krml obj/FStar_Heap.krml obj/FStar_ST.krml obj/FStar_All.krml obj/FStar_List.krml obj/Vale_Lib_Seqs.krml obj/Vale_Def_TypesNative_s.krml obj/Vale_Arch_TypesNative.krml obj/Vale_Def_Words_Seq.krml obj/Vale_Arch_Types.krml obj/Vale_Def_Prop_s.krml obj/Vale_Arch_MachineHeap_s.krml obj/Vale_Arch_MachineHeap.krml obj/FStar_Option.krml obj/FStar_Monotonic_HyperHeap.krml obj/FStar_Monotonic_HyperStack.krml obj/FStar_HyperStack.krml obj/FStar_HyperStack_ST.krml obj/FStar_Universe.krml obj/FStar_GSet.krml obj/FStar_ModifiesGen.krml obj/FStar_Reflection_Const.krml obj/FStar_Order.krml obj/FStar_Reflection_Builtins.krml obj/FStar_Reflection_Derived.krml obj/FStar_Reflection_Derived_Lemmas.krml obj/FStar_Reflection.krml obj/FStar_Tactics_Print.krml obj/FStar_Tactics_SyntaxHelpers.krml obj/FStar_Tactics_Util.krml obj/FStar_IndefiniteDescription.krml obj/FStar_Reflection_Formula.krml obj/FStar_Tactics_Derived.krml obj/FStar_Tactics_Logic.krml obj/FStar_Tactics.krml obj/FStar_BigOps.krml obj/LowStar_Monotonic_Buffer.krml obj/LowStar_Buffer.krml obj/LowStar_Modifies.krml obj/LowStar_BufferView_Down.krml obj/FStar_UInt64.krml obj/FStar_UInt16.krml obj/LowStar_BufferView_Up.krml obj/Vale_Interop_Views.krml obj/LowStar_ImmutableBuffer.krml obj/Vale_Arch_HeapTypes_s.krml obj/Vale_Interop_Types.krml obj/Vale_Interop_Heap_s.krml obj/LowStar_ModifiesPat.krml obj/LowStar_BufferView.krml obj/Vale_Lib_BufferViewHelpers.krml obj/Vale_Interop.krml obj/Vale_X64_Machine_s.krml obj/Vale_Lib_Map16.krml obj/Vale_Arch_HeapImpl.krml obj/Vale_Arch_Heap.krml obj/Vale_X64_Instruction_s.krml obj/Vale_X64_Bytes_Code_s.krml obj/Vale_AES_AES_s.krml obj/Vale_Math_Poly2_Defs_s.krml obj/Vale_Math_Poly2_s.krml obj/Vale_Math_Poly2_Bits_s.krml obj/FStar_Int.krml obj/FStar_Int64.krml obj/FStar_Int32.krml obj/FStar_Int16.krml obj/FStar_Int8.krml obj/FStar_Int_Cast.krml obj/FStar_UInt128.krml obj/FStar_Int_Cast_Full.krml obj/FStar_Int128.krml obj/Lib_IntTypes.krml obj/Lib_UpdateMulti.krml obj/Lib_LoopCombinators.krml obj/Lib_RawIntTypes.krml obj/Lib_Sequence.krml obj/Lib_ByteSequence.krml obj/Spec_Blake2.krml obj/Spec_Hash_Definitions.krml obj/Spec_Hash_Lemmas0.krml obj/Spec_Hash_PadFinish.krml obj/Spec_Loops.krml obj/Spec_SHA2_Constants.krml obj/Spec_SHA2.krml obj/Vale_X64_CryptoInstructions_s.krml obj/Vale_X64_CPU_Features_s.krml obj/Vale_X64_Instructions_s.krml obj/Vale_X64_Machine_Semantics_s.krml obj/Vale_Interop_Base.krml obj/Vale_X64_Memory.krml obj/Vale_X64_Stack_i.krml obj/Meta_Attribute.krml obj/FStar_HyperStack_All.krml obj/Spec_SHA1.krml obj/Spec_MD5.krml obj/Spec_Agile_Hash.krml obj/Spec_Hash_Lemmas.krml obj/Spec_Hash_Incremental.krml obj/LowStar_BufferOps.krml obj/C_Loops.krml obj/Lib_Loops.krml obj/FStar_Endianness.krml obj/LowStar_Endianness.krml obj/Lib_Memzero0.krml obj/LowStar_ConstBuffer.krml obj/Lib_Buffer.krml obj/Lib_ByteBuffer.krml obj/Lib_IntVector_Intrinsics.krml obj/Spec_GaloisField.krml obj/Spec_AES.krml obj/Lib_IntVector.krml obj/Hacl_Impl_Blake2_Core.krml obj/Hacl_Impl_Blake2_Constants.krml obj/Hacl_Impl_Blake2_Generic.krml obj/FStar_Krml_Endianness.krml obj/Hacl_Hash_Lemmas.krml obj/Hacl_Hash_Definitions.krml obj/Hacl_Hash_PadFinish.krml obj/Hacl_Hash_MD.krml obj/Spec_SHA2_Lemmas.krml obj/FStar_Float.krml obj/FStar_IO.krml obj/Vale_X64_BufferViewStore.krml obj/Vale_X64_Memory_Sems.krml obj/Vale_Def_PossiblyMonad.krml obj/Vale_X64_Flags.krml obj/Vale_X64_Stack_Sems.krml obj/Vale_X64_Regs.krml obj/Vale_X64_State.krml obj/Vale_X64_StateLemmas.krml obj/Vale_Arch_HeapLemmas.krml obj/Vale_X64_Lemmas.krml obj/Vale_X64_Print_s.krml obj/Vale_X64_Decls.krml obj/Vale_X64_MemoryAdapters.krml obj/Vale_Interop_Assumptions.krml obj/Vale_Interop_X64.krml obj/Vale_AsLowStar_ValeSig.krml obj/Vale_AsLowStar_LowStarSig.krml obj/Vale_AsLowStar_MemoryHelpers.krml obj/Vale_X64_QuickCode.krml obj/Vale_X64_QuickCodes.krml obj/Vale_X64_Taint_Semantics.krml obj/Vale_X64_InsLemmas.krml obj/Vale_X64_InsBasic.krml obj/Vale_X64_InsMem.krml obj/Vale_X64_InsVector.krml obj/Vale_X64_InsStack.krml obj/Vale_X64_Stack.krml obj/Vale_SHA_SHA_helpers.krml obj/Vale_X64_InsSha.krml obj/Vale_SHA_X64.krml obj/Vale_AsLowStar_Wrapper.krml obj/Vale_Stdcalls_X64_Sha.krml obj/FStar_BV.krml obj/FStar_Reflection_Arith.krml obj/FStar_Tactics_BV.krml obj/Vale_Lib_Bv_s.krml obj/Vale_Math_Bits.krml obj/Vale_Lib_Tactics.krml obj/Vale_Poly1305_Bitvectors.krml obj/FStar_Algebra_CommMonoid.krml obj/FStar_Tactics_CanonCommSemiring.krml obj/Vale_Math_Lemmas_Int.krml obj/FStar_Tactics_Canon.krml obj/Vale_Poly1305_Spec_s.krml obj/Vale_Poly1305_Math.krml obj/Vale_Poly1305_Util.krml obj/Vale_Poly1305_X64.krml obj/Vale_Stdcalls_X64_Poly.krml obj/Vale_Wrapper_X64_Poly.krml obj/Vale_Arch_BufferFriend.krml obj/Vale_SHA_Simplify_Sha.krml obj/Vale_Wrapper_X64_Sha.krml obj/EverCrypt_TargetConfig.krml obj/Hacl_Blake2b_32.krml obj/Hacl_Blake2s_32.krml obj/Spec_Hash_Incremental_Lemmas.krml obj/Hacl_Hash_Blake2_Lemmas.krml obj/Hacl_Hash_Core_Blake2.krml obj/Hacl_Hash_Blake2.krml obj/Hacl_Hash_Core_SHA2.krml obj/Hacl_Hash_SHA2.krml obj/Hacl_Hash_Core_SHA1.krml obj/Hacl_Hash_SHA1.krml obj/Hacl_Hash_Core_MD5.krml obj/Hacl_Hash_MD5.krml obj/C.krml obj/FStar_Char.krml obj/FStar_String.krml obj/C_String.krml obj/C_Failure.krml obj/FStar_Integers.krml obj/EverCrypt_StaticConfig.krml obj/Vale_Lib_Basic.krml obj/Vale_Lib_X64_Cpuid.krml obj/Vale_Lib_X64_Cpuidstdcall.krml obj/Vale_Stdcalls_X64_Cpuid.krml obj/Vale_Wrapper_X64_Cpuid.krml obj/EverCrypt_AutoConfig2.krml obj/EverCrypt_Helpers.krml obj/EverCrypt_Hash.krml obj/Hacl_Impl_Curve25519_Lemmas.krml obj/Hacl_Spec_Bignum_Definitions.krml obj/Hacl_Spec_Bignum_Convert.krml obj/Spec_Curve25519_Lemmas.krml obj/Spec_Curve25519.krml obj/Hacl_Spec_Curve25519_Field64_Definition.krml obj/Hacl_Spec_Curve25519_Field51_Definition.krml obj/Hacl_Spec_Curve25519_Field51_Lemmas.krml obj/Hacl_Spec_Curve25519_Field51.krml obj/Hacl_Impl_Curve25519_Fields_Core.krml obj/Hacl_Impl_Curve25519_Field51.krml obj/Hacl_Spec_Curve25519_AddAndDouble.krml obj/Hacl_Spec_Bignum_Base.krml obj/Hacl_Spec_Bignum_Lib.krml obj/Hacl_Spec_Bignum_Comparison.krml obj/Lib_Sequence_Lemmas.krml obj/Lib_Vec_Lemmas.krml obj/Hacl_Spec_Lib.krml obj/Hacl_Spec_Bignum_Addition.krml obj/Hacl_Spec_Bignum_Multiplication.krml obj/Hacl_Spec_Bignum_Squaring.krml obj/Hacl_Spec_Karatsuba_Lemmas.krml obj/Hacl_Spec_Bignum_Karatsuba.krml obj/Hacl_Spec_Bignum.krml obj/Hacl_Spec_Curve25519_Field64_Lemmas.krml obj/Hacl_Spec_Curve25519_Field64_Core.krml obj/Hacl_Spec_Curve25519_Field64.krml obj/Hacl_Impl_Curve25519_Field64.krml obj/Hacl_Impl_Curve25519_Fields.krml obj/Hacl_Impl_Curve25519_AddAndDouble.krml obj/Spec_Agile_HMAC.krml obj/Hacl_HMAC.krml obj/Hacl_Streaming_Interface.krml obj/Lib_UpdateMulti_Lemmas.krml obj/Hacl_Streaming_Spec.krml obj/Hacl_Streaming_Functor.krml obj/Hacl_Streaming_MD.krml obj/Hacl_Bignum_Definitions.krml obj/Lib_IntTypes_Intrinsics.krml obj/Hacl_Bignum_Base.krml obj/Hacl_Bignum_Lib.krml obj/Hacl_Bignum_Comparison.krml obj/FStar_List_Pure_Base.krml obj/FStar_List_Pure_Properties.krml obj/FStar_List_Pure.krml obj/Meta_Interface.krml obj/Hacl_Spec_Curve25519_Finv.krml obj/Hacl_Impl_Curve25519_Finv.krml obj/Hacl_Impl_Curve25519_Generic.krml obj/Hacl_Meta_Curve25519.krml obj/FStar_Tactics_Typeclasses.krml obj/Lib_Exponentiation.krml obj/FStar_Math_Euclid.krml obj/FStar_Math_Fermat.krml obj/Lib_NatMod.krml obj/Spec_Ed25519_PointOps.krml obj/Spec_Ed25519_Lemmas.krml obj/Spec_Exponentiation.krml obj/Spec_Ed25519.krml obj/Hacl_Impl_Ed25519_Field51.krml obj/Hacl_Curve25519_51.krml obj/Hacl_Bignum25519.krml obj/Hacl_Impl_Ed25519_PointDouble.krml obj/Hacl_Spec_BignumQ_Definitions.krml obj/Hacl_Spec_BignumQ_Lemmas.krml obj/Hacl_Spec_BignumQ_Mul.krml obj/Hacl_Impl_Lib.krml obj/Hacl_Bignum_Addition.krml obj/Hacl_Bignum_Multiplication.krml obj/Hacl_Bignum_Karatsuba.krml obj/Hacl_Spec_PrecompTable.krml obj/Hacl_Impl_PrecompTable.krml obj/Hacl_Impl_Ed25519_Pow2_252m2.krml obj/Lib_IntTypes_Compatibility.krml obj/Hacl_Impl_Ed25519_RecoverX.krml obj/Hacl_Impl_Ed25519_PointDecompress.krml obj/Hacl_Impl_BignumQ_Mul.krml obj/Hacl_Impl_Store56.krml obj/Hacl_Impl_Load56.krml obj/Hacl_Streaming_SHA2.krml obj/Hacl_Impl_SHA512_ModQ.krml obj/Hacl_Impl_Ed25519_PointEqual.krml obj/Hacl_Impl_Ed25519_PointNegate.krml obj/Hacl_Impl_Ed25519_PointAdd.krml obj/Hacl_Bignum_Convert.krml obj/Hacl_Bignum.krml obj/Hacl_Impl_Exponentiation.krml obj/Hacl_Impl_MultiExponentiation.krml obj/Hacl_Impl_Ed25519_Ladder.krml obj/Hacl_Impl_Ed25519_Verify.krml obj/Hacl_Impl_Ed25519_PointCompress.krml obj/Hacl_Impl_Ed25519_Sign.krml obj/Hacl_Ed25519.krml obj/EverCrypt_Ed25519.krml obj/EverCrypt_HMAC.krml obj/PARseL.krml -tmpdir dist/ -skip-compilation -minimal -add-include "krml/internal/target.h" -add-include "krml/internal/types.h" -add-include "krml/lowstar_endianness.h" -add-include <stdint.h> -add-include <stdbool.h> -add-include <string.h> -fparentheses -o lowToC.a -library Vale.Stdcalls.* -no-prefix Vale.Stdcalls.* -static-header Vale.Inline.* -library Vale.Inline.X64.Fadd_inline -library Vale.Inline.X64.Fmul_inline -library Vale.Inline.X64.Fswap_inline -library Vale.Inline.X64.Fsqr_inline -no-prefix Vale.Inline.X64.Fadd_inline -no-prefix Vale.Inline.X64.Fmul_inline -no-prefix Vale.Inline.X64.Fswap_inline -no-prefix Vale.Inline.X64.Fsqr_inline -no-prefix PARseL -bundle EverCrypt.Hash=EverCrypt,EverCrypt.*,Meta.*,Hacl.*,Vale.*,Spec.*,Lib.* -library EverCrypt.AutoConfig2 -bundle LowStar.* -bundle Prims,C.Failure,C,C.String,C.Loops,Spec.Loops,C.Endianness,FStar.*[rename=lowToC_Krmllib] -library Meta.*,Hacl.*,Vale.*,Spec.*,Lib.* -ccopts -DLib_IntVector_Intrinsics_vec256=void*,-DLib_IntVector_Intrinsics_vec128=void* -warn-error +9
  F* version: 52fe4347
  KaRaMeL version: d67210df
 */

#ifndef __lowToC_Krmllib_H
#define __lowToC_Krmllib_H




#include "krml/internal/target.h"
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
static inline FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a);


#define __lowToC_Krmllib_H_DEFINED
#endif
