module PARseL

open FStar.IO
open FStar.HyperStack.All
open FStar.UInt8
open FStar.UInt64
open FStar.UInt32
open FStar.Int32
open FStar.Integers

open Lib.Buffer

open EverCrypt.HMAC
open Lib.IntTypes
open Spec.Hash.Definitions
open FStar.HyperStack.ST

module B = LowStar.Buffer
module HS = FStar.HyperStack
module ST = FStar.HyperStack.ST
module Cast = FStar.Int.Cast
module G = FStar.Ghost
module I = Lib.IntTypes
module BB = Lib.ByteBuffer

#set-options "--z3rlimit 5000 --initial_fuel 10 --max_fuel 1000 --initial_ifuel 10 --max_ifuel 1000"

val int_to_uint32: a:Prims.int -> Tot (b:UInt32.t {UInt32.v b = a % pow2 32})
let int_to_uint32 x = UInt32.uint_to_t (x % pow2 32)

////////// seL4 APIs in SP at runtime //////////
type seL4_Word = uint32 //uint64 
type seL4_CPtr = seL4_Word // in sel4/simple_types.h
let seL4_MsgMaxLength:size_t = 120ul

noeq type seL4_MessageInfo_t = {
  words: B.lbuffer pub_uint64 1;
}

type mbuffer (a:Type0) (len:nat) =
  b:B.lbuffer a len{B.frameOf b == HS.root /\ B.recallable b}

type mpointer (a:Type0) (rel:B.srel a) =
  b:B.mbuffer a rel rel{B.frameOf b == HS.root /\ B.recallable b /\ B.length b == 1}

let t:Type0 = bool & bool

assume val t_rel : B.srel (G.erased t)

noeq 
type seL4_IPCBuffer = {
  msg           : mbuffer seL4_Word 120; // seL4_MsgMaxLength = 120ul but lbuffer requires type nat
}

inline_for_extraction
let alg: EverCrypt.HMAC.supported_alg = SHA2_256

noeq
type state = {
  hmac_key: mbuffer uint8 (block_length alg);//64 for SHA2-256
  sign_key: mbuffer uint8 32; //private key for EdDSA
  mmap: mbuffer uint8 192;
  ipc_buffer: ipc:seL4_IPCBuffer {
    B.(all_disjoint [loc_buffer hmac_key;
                     loc_buffer sign_key;
                     loc_buffer mmap;
                     loc_buffer ipc.msg;                     
                    ])
  };
  user_process_counter:UInt64.t;
  eP_UP_BADGE:UInt64.t;
}

val st (_:unit):state

let st_liveness (st:state) (h:HS.mem): Type0 = 
  B.all_live h [
    B.buf st.hmac_key;
    B.buf st.sign_key;
    B.buf st.mmap;
    B.buf st.ipc_buffer.msg
  ]

inline_for_extraction noextract
let recall_ipcbuffer_liveness (ipc_buffer: seL4_IPCBuffer) 
: Stack unit
  (requires fun _ -> True)
  (ensures fun h0 _ h1 -> h0 == h1 /\ B.live h1 ipc_buffer.msg) // /\ B.live h1 ipc_buffer.caps_or_badges)
= B.recall ipc_buffer.msg
  //B.recall ipc_buffer.caps_or_badges

inline_for_extraction noextract
let recall_st_liveness (st: state) 
: Stack unit
  (requires fun _ -> True)
  (ensures fun h0 _ h1 -> h0 == h1 /\ st_liveness st h1) // /\ B.live h1 ipc_buffer.caps_or_badges)
= B.recall st.hmac_key;
  B.recall st.sign_key;
  B.recall st.mmap;
  B.recall st.ipc_buffer.msg

let st_var: state = 
  let hmac_key = B.gcmalloc HS.root (I.u8 0) (int_to_uint32 (block_length alg)) in //32ul in
  let sign_key = B.gcmalloc HS.root (I.u8 0) 32ul in
  let mmap = B.gcmalloc HS.root (I.u8 0) 192ul in
  let msg = B.gcmalloc HS.root (I.u32 0) 120ul in 
  let ipc_buffer = {
    msg = msg;
  } in
  let user_process_counter = 0UL in
  let eP_UP_BADGE = 38UL in
  {
    hmac_key = hmac_key;
    sign_key = sign_key;
    mmap = mmap;
    ipc_buffer = ipc_buffer;
    user_process_counter = user_process_counter;
    eP_UP_BADGE = eP_UP_BADGE
  }
  
let st _ = st_var

assume val seL4_GetMR 
( i : size_t )
: Stack seL4_Word 
( requires fun h0 -> (size_v i < 120) /\ (size_v i >= 0) ) 
( ensures fun h0 a h1 -> B.(modifies loc_none h0 h1) /\ a == B.get h1 (st ()).ipc_buffer.msg (v i)) 

assume val seL4_SetMR
(i : size_t { size_v i < size_v seL4_MsgMaxLength /\ size_v i >= 0 })
( mr : seL4_Word )
: Stack unit
( requires fun h0 -> True) 
( ensures fun h0 _ h1 -> (B.(modifies (loc_buffer_from_to (st _).ipc_buffer.msg (size (size_v i)) (size ((size_v i)+1)) ) h0 h1)) /\ B.get h1 (st _).ipc_buffer.msg (size_v i) == mr)

assume val seL4_Recv
( src : seL4_CPtr )
( sender : B.pointer seL4_Word {B.(all_disjoint [loc_buffer (st ()).hmac_key; loc_buffer (st ()).sign_key; loc_buffer (st ()).mmap; loc_buffer (st ()).ipc_buffer.msg; loc_buffer sender])} )
: Stack seL4_MessageInfo_t 
( requires fun _ -> True )
( ensures fun h0 a h1 -> (B.live h1 sender) 
                         /\ B.(modifies (loc_buffer sender) h0 h1) 
                         /\ (B.(all_disjoint [loc_buffer a.words; loc_buffer (st ()).hmac_key; loc_buffer (st ()).sign_key;  loc_buffer (st ()).mmap; loc_buffer (st ()).ipc_buffer.msg; loc_buffer sender]) )
                         /\ (FStar.Integers.within_bounds (FStar.Integers.Unsigned FStar.Integers.W64) (I.sec_int_v (B.deref h1 sender) - FStar.Integers.v (st ()).eP_UP_BADGE)) 
                         /\ (I.sec_int_v (B.deref h1 sender) - FStar.Integers.v (st ()).eP_UP_BADGE + 32 <= (B.length (st ()).mmap) ) ) 

assume val seL4_Reply
( msgInfo : seL4_MessageInfo_t )
: Stack unit (fun _ -> True) (fun h0 _ h1 -> B.(modifies loc_none h0 h1))

////////// SP //////////

val test_concat_hash_and_hmac:
a: EverCrypt.HMAC.supported_alg ->
key_len: size_nat ->
key: B.lbuffer uint8 key_len {Spec.Agile.HMAC.keysized a (B.length key)} ->
len0:size_nat -> 
s0:B.lbuffer uint8 len0 -> 
len1:size_nat -> 
s1:B.lbuffer uint8 len1 -> 
len2: size_nat {(len0 + len1 + len2 <= max_size_t) /\ (len0 + len1 + len2 <= max_input_length a) } ->
s2:B.lbuffer uint8 len2 ->
concat_res:B.lbuffer uint8 (len0 + len1 + len2) -> 
hash_res: B.lbuffer uint8 (hash_length a) {B.length hash_res + Spec.Hash.Definitions.block_length a < pow2 32} ->
hmac_res: B.lbuffer uint8 (hash_length a) ->
Stack unit
(requires fun h -> B.live h s0 /\ B.live h s1 /\ B.live h s2 /\ B.live h concat_res /\ B.live h hash_res /\ B.live h hmac_res /\ B.live h key 
                  /\ B.all_disjoint [B.loc_buffer s0;B.loc_buffer s1;B.loc_buffer s2;B.loc_buffer concat_res; B.loc_buffer hash_res; B.loc_buffer hmac_res; B.loc_buffer key])
(ensures fun h0 _ h1 -> EverCrypt.HMAC.key_and_data_fits a ;
                        B.modifies (B.loc_buffer concat_res `B.loc_union` B.loc_buffer hash_res `B.loc_union` B.loc_buffer hmac_res) h0 h1 
                         /\ ( (B.as_seq h1 concat_res) == (Lib.Sequence.concat #uint8 #(len0+len1) #len2 (Lib.Sequence.concat #uint8 #len0 #len1 (B.as_seq h0 s0) (B.as_seq h0 s1)) (B.as_seq h0 s2)) )
                         /\ ( (B.as_seq h1 hash_res) == (Spec.Agile.Hash.hash a (B.as_seq h1 concat_res)) )
                         /\ ( (B.as_seq h1 hmac_res) == (Spec.Agile.HMAC.hmac a (B.as_seq h0 key) (B.as_seq h1 hash_res)) )
)

let test_concat_hash_and_hmac alg key_len key l0 s0 l1 s1 l2 s2 concat_res hash_res hmac_res =
  push_frame();
  let h0 = ST.get() in
  Lib.Buffer.concat3 #MUT #MUT #MUT #uint8 (size l0) s0 (size l1) s1 (size l2) s2 concat_res;
  let h1 = ST.get() in
  assert ((B.as_seq h1 concat_res) == (Lib.Sequence.concat #uint8 #(l0+l1) #l2 (Lib.Sequence.concat #uint8 #l0 #l1 (B.as_seq h0 s0) (B.as_seq h0 s1)) (B.as_seq h0 s2)));
  EverCrypt.Hash.hash alg hash_res concat_res (size (l0+l1+l2));
  let h2 = ST.get() in
  assert ((B.as_seq h2 hash_res) == (Spec.Agile.Hash.hash alg (B.as_seq h1 concat_res))); 
  EverCrypt.HMAC.compute alg hmac_res key (size key_len) hash_res (size (hash_length alg));
  let h3 = ST.get() in
  assert ((B.as_seq h3 hmac_res) == (Spec.Agile.HMAC.hmac alg (B.as_seq h0 key) (B.as_seq h2 hash_res)));
  pop_frame();
  ()

val test_concat_hash_and_sign_pke: // EdDSA with 32-byte private key and 64-byte signature
a: EverCrypt.HMAC.supported_alg ->
private_key: B.lbuffer uint8 32 ->
len0:size_nat -> 
s0:B.lbuffer uint8 len0 -> 
len1:size_nat -> 
s1:B.lbuffer uint8 len1 -> 
len2: size_nat {(len0 + len1 + len2 <= max_size_t) /\ (len0 + len1 + len2 <= max_input_length a) } ->
s2:B.lbuffer uint8 len2 ->
concat_res:B.lbuffer uint8 (len0 + len1 + len2) -> 
hash_res: B.lbuffer uint8 (hash_length a) {B.length hash_res + Spec.Hash.Definitions.block_length a < pow2 32} ->
sign_res: B.lbuffer uint8 64 ->
Stack unit
(requires fun h -> B.live h s0 /\ B.live h s1 /\ B.live h s2 /\ B.live h concat_res /\ B.live h hash_res /\ B.live h sign_res /\ B.live h private_key 
                  /\ B.all_disjoint [B.loc_buffer s0;B.loc_buffer s1;B.loc_buffer s2;B.loc_buffer concat_res; B.loc_buffer hash_res; B.loc_buffer sign_res; B.loc_buffer private_key])
(ensures fun h0 _ h1 -> B.modifies (B.loc_buffer concat_res `B.loc_union` B.loc_buffer hash_res `B.loc_union` B.loc_buffer sign_res) h0 h1 
                         /\ ( (B.as_seq h1 concat_res) == (Lib.Sequence.concat #uint8 #(len0+len1) #len2 (Lib.Sequence.concat #uint8 #len0 #len1 (B.as_seq h0 s0) (B.as_seq h0 s1)) (B.as_seq h0 s2)) )
                         /\ ( (B.as_seq h1 hash_res) == (Spec.Agile.Hash.hash a (B.as_seq h1 concat_res)) )
                         /\ ( (B.as_seq h1 sign_res) == (Spec.Ed25519.sign (B.as_seq h0 private_key) (B.as_seq h1 hash_res)) )
)

let test_concat_hash_and_sign_pke alg key l0 s0 l1 s1 l2 s2 concat_res hash_res sign_res =
  push_frame();
  let h0 = ST.get() in
  Lib.Buffer.concat3 #MUT #MUT #MUT #uint8 (size l0) s0 (size l1) s1 (size l2) s2 concat_res;
  let h1 = ST.get() in
  assert ((B.as_seq h1 concat_res) == (Lib.Sequence.concat #uint8 #(l0+l1) #l2 (Lib.Sequence.concat #uint8 #l0 #l1 (B.as_seq h0 s0) (B.as_seq h0 s1)) (B.as_seq h0 s2)));
  EverCrypt.Hash.hash alg hash_res concat_res (size (l0+l1+l2));
  let h2 = ST.get() in
  assert ((B.as_seq h2 hash_res) == (Spec.Agile.Hash.hash alg (B.as_seq h1 concat_res))); 
  EverCrypt.Ed25519.sign sign_res key (size (hash_length alg)) hash_res;
  let h3 = ST.get() in
  assert ((B.as_seq h3 sign_res) == (Spec.Ed25519.sign (B.as_seq h0 key) (B.as_seq h2 hash_res)));
  pop_frame();
  ()

val attest 
(ep_up: seL4_CPtr {I.sec_int_v ep_up >= 0}) 
: Stack unit 
(requires fun _ -> True)
(ensures fun h0 _ h1 -> ((B.as_seq h0 (st ()).hmac_key) == (B.as_seq h1 (st ()).hmac_key))  // key invariance
                        /\ ((B.as_seq h0 (st ()).mmap) == (B.as_seq h1 (st ()).mmap)) ) // mmap invariance
                        ///\ (B.(modifies (B.loc_buffer (st ()).ipc_buffer.msg) h0 h1)) )

let attest ep_up =
  let s = st () in
  recall_st_liveness s;
  let h0 = ST.get () in
  push_frame();
  // ** Getting sender_badge information by seL4_Recv (trick: use a pointer instead of giving the address of sender_badge variable)
  let sender_badge_ptr: B.pointer seL4_Word = B.alloca (u32 0) 1ul in // (u64 0) 1ul in
  let tag = seL4_Recv ep_up sender_badge_ptr in
  let sender_badge = B.index sender_badge_ptr 0ul in
  assert (B.(all_disjoint [loc_buffer sender_badge_ptr; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  // ** Getting challenge value (uint64) from the user process using seL4_GetMR
  let challenge_from_process: B.lbuffer seL4_Word 8 = B.alloca (u32 0) 8ul in //B.lbuffer seL4_Word 4 = B.alloca (u64 0) 4ul in    
  assert (B.(all_disjoint [loc_buffer challenge_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  B.upd challenge_from_process 0ul (seL4_GetMR (size 0));
  B.upd challenge_from_process 1ul (seL4_GetMR (size 1));
  B.upd challenge_from_process 2ul (seL4_GetMR (size 2));
  B.upd challenge_from_process 3ul (seL4_GetMR (size 3));
  B.upd challenge_from_process 4ul (seL4_GetMR (size 4));
  B.upd challenge_from_process 5ul (seL4_GetMR (size 5));
  B.upd challenge_from_process 6ul (seL4_GetMR (size 6));
  B.upd challenge_from_process 7ul (seL4_GetMR (size 7));
  let chal: buffer uint8 = create (size 32) (u8 0) in
  assert (B.(all_disjoint [loc_buffer chal; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  BB.uints_to_bytes_be #U32 #SEC (size 8) chal challenge_from_process; // BB.uints_to_bytes_be #U64 #SEC (size 4) chal challenge_from_process;
  assert (B.(all_disjoint [loc_buffer chal; loc_buffer challenge_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  let h = ST.get () in
  assert (B.live h chal); // this assertion is not necessary but it would reduce the runtime by helping the later assertion
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap);
  assert (B.as_seq h0 s.hmac_key == B.as_seq h s.hmac_key);
  // ** Acknowledge the user process that we got the challenge
  seL4_SetMR (size 0) (u32 0);   //seL4_SetMR (size 0) (u64 0);   
  seL4_Reply tag;
  // ** Again receiving the sender_badge information to get the public key of the user process
  let tag = seL4_Recv ep_up sender_badge_ptr in
  let sender_badge = B.index sender_badge_ptr 0ul in //update the sender_badge from sender_badge_ptr
  assert (B.(all_disjoint [loc_buffer sender_badge_ptr; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  // ** Getting public key (UInt64) from the user process using seL4_GetMR
  let pk_from_process: B.lbuffer seL4_Word 8 = B.alloca (u32 0) 8ul in //B.lbuffer seL4_Word 4 = B.alloca (u64 0) 4ul in  
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));  
  B.upd pk_from_process 0ul (seL4_GetMR (size 0));
  let h = ST.get () in
  // assertion for seL4_GetMR correctness (without warning)
  let pk_from_process_0 = B.index pk_from_process 0ul in
  let ipc_buffer_msg_0 = B.index s.ipc_buffer.msg 0ul in
  assert (pk_from_process_0 == ipc_buffer_msg_0);
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  assert (B.as_seq h0 s.hmac_key == B.as_seq h s.hmac_key);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); 
  B.upd pk_from_process 1ul (seL4_GetMR (size 1));
  let pk_from_process_1 = B.index pk_from_process 1ul in
  let ipc_buffer_msg_1 = B.index s.ipc_buffer.msg 1ul in
  assert (pk_from_process_1 == ipc_buffer_msg_1);
  B.upd pk_from_process 2ul (seL4_GetMR (size 2));
  let pk_from_process_2 = B.index pk_from_process 2ul in
  let ipc_buffer_msg_2 = B.index s.ipc_buffer.msg 2ul in
  assert (pk_from_process_2 == ipc_buffer_msg_2);
  B.upd pk_from_process 3ul (seL4_GetMR (size 3));
  let pk_from_process_3 = B.index pk_from_process 3ul in
  let ipc_buffer_msg_3 = B.index s.ipc_buffer.msg 3ul in
  assert (pk_from_process_3 == ipc_buffer_msg_3);
  B.upd pk_from_process 4ul (seL4_GetMR (size 4));
  let pk_from_process_4 = B.index pk_from_process 4ul in
  let ipc_buffer_msg_4 = B.index s.ipc_buffer.msg 4ul in
  assert (pk_from_process_4 == ipc_buffer_msg_4);
  B.upd pk_from_process 5ul (seL4_GetMR (size 5));
  let pk_from_process_5 = B.index pk_from_process 5ul in
  let ipc_buffer_msg_5 = B.index s.ipc_buffer.msg 5ul in
  assert (pk_from_process_5 == ipc_buffer_msg_5);
  B.upd pk_from_process 6ul (seL4_GetMR (size 6));
  let pk_from_process_6 = B.index pk_from_process 6ul in
  let ipc_buffer_msg_6 = B.index s.ipc_buffer.msg 6ul in
  assert (pk_from_process_6 == ipc_buffer_msg_6);
  B.upd pk_from_process 7ul (seL4_GetMR (size 7));
  let pk_from_process_7 = B.index pk_from_process 7ul in
  let ipc_buffer_msg_7 = B.index s.ipc_buffer.msg 7ul in
  assert (pk_from_process_7 == ipc_buffer_msg_7);
  let h = ST.get () in
  assert (B.live h chal); // this assertion is necessary
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  assert (B.disjoint s.hmac_key pk_from_process);
  assert (B.as_seq h0 s.hmac_key == B.as_seq h s.hmac_key);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); // this is necessary
  let pk: buffer uint8 = create (size 32) (u8 0) in
  BB.uints_to_bytes_be #U32 #SEC (size 8) pk pk_from_process; //BB.uints_to_bytes_be #U64 #SEC (size 4) pk pk_from_process;
  assert (B.(all_disjoint [loc_buffer pk; loc_buffer pk_from_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  // ** memcpy measurement from mmap to UInt8.t buffer (att_hash)
  let starting_point = (I.sec_int_v sender_badge) - (UInt64.v s.eP_UP_BADGE) in  
  let starting_point_uint32:UInt32.t = int_to_uint32 starting_point in
  recall_st_liveness s;
  let measurement_process = B.sub s.mmap starting_point_uint32 32ul in // subbuffer of mmap (UInt8.t buffer) starting from [sender_badge - EP_UP_BADGE] with length HMAC_OUTPUT_LEN (32ul)
  assert (B.(all_disjoint [loc_buffer measurement_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  // ** Sign the chal, pk, and measurement_process with the private key
  let h = ST.get () in 
  assert (B.live h chal /\ B.live h pk /\ B.live h measurement_process);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); // this is necessary
  // sign and hash result sizes are 32 bytes, assuming SHA2_256
  let sign_result_u8 : buffer uint8 = create (size (hash_length alg)) (u8 0) in
  let tmp_concat: buffer uint8 = create (size 96) (u8 0) in
  let tmp_hash: buffer uint8 = create (size (hash_length alg)) (u8 0) in
  test_concat_hash_and_hmac alg (block_length alg) s.hmac_key 32 chal 32 pk 32 measurement_process tmp_concat tmp_hash sign_result_u8;
  let h' = ST.get () in
  assert (B.(all_disjoint [loc_buffer sign_result_u8; loc_buffer tmp_concat; loc_buffer tmp_hash; loc_buffer chal; loc_buffer pk; loc_buffer measurement_process; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  // assertion for functional correctness of "sign"
  assert (
          B.as_seq h' sign_result_u8 == 
            Spec.Agile.HMAC.hmac alg (B.as_seq h0 s.hmac_key) 
              (Spec.Agile.Hash.hash alg 
                  (Lib.Sequence.concat #uint8 #64 #32 (Lib.Sequence.concat #uint8 #32 #32 (B.as_seq h chal) (B.as_seq h pk)) (B.as_seq h measurement_process)) 
              ) 
          );
  assert (B.as_seq h0 s.mmap == B.as_seq h' s.mmap); // this is necessary
  // // convert sign_result_u8 to sign_result_u64 (uint64 buffer) and send it to UP using seL4_SetMR and seL4_Reply
  // //convert uint8 to uint64
  // convert sign_result_u8 to sign_result_u32 (uint32 buffer) and send it to UP using seL4_SetMR and seL4_Reply
  //convert uint8 to uint32
  assert (hash_length alg == 32); // this is true for SHA2_256
  // let size_of_sign_result_u64 = (hash_length alg) / 8 in // hash_length SHA2_256 = 32, so this should be 4ul
  // assert (size_of_sign_result_u64 == 4); // this is true for SHA2_256
  let size_of_sign_result_u32 = (hash_length alg) / 4 in // hash_length SHA2_256 = 32, so this should be 8ul
  assert (size_of_sign_result_u32 == 8); // this is true for SHA2_256
  // let sign_result_u64: lbuffer uint64 (size size_of_sign_result_u64) = create #uint64 (size size_of_sign_result_u64) (u64 0) in
  // BB.uints_from_bytes_be #U64 #SEC #(size size_of_sign_result_u64) sign_result_u64 sign_result_u8;
  let sign_result_u32: lbuffer uint32 (size size_of_sign_result_u32) = create #uint32 (size size_of_sign_result_u32) (u32 0) in
  BB.uints_from_bytes_be #U32 #SEC #(size size_of_sign_result_u32) sign_result_u32 sign_result_u8;
  // assert (B.(all_disjoint [loc_buffer #uint64 #(B.trivial_preorder uint64) #(B.trivial_preorder uint64) sign_result_u64; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  assert (B.(all_disjoint [loc_buffer #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32; loc_buffer s.hmac_key; loc_buffer s.ipc_buffer.msg]));
  let tmp_index_0 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 0ul in
  seL4_SetMR (size 0) tmp_index_0;
  let tmp_index_1 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 1ul in
  seL4_SetMR (size 1) tmp_index_1;
  let tmp_index_2 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 2ul in
  seL4_SetMR (size 2) tmp_index_2;
  let tmp_index_3 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 3ul in
  seL4_SetMR (size 3) tmp_index_3;
  let tmp_index_4 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 4ul in
  seL4_SetMR (size 4) tmp_index_4;
  let tmp_index_5 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 5ul in
  seL4_SetMR (size 5) tmp_index_5;
  let tmp_index_6 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 6ul in
  seL4_SetMR (size 6) tmp_index_6;
  let tmp_index_7 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 7ul in
  seL4_SetMR (size 7) tmp_index_7;
  seL4_Reply tag;
  let h = ST.get () in
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap);
  pop_frame();
  let h1 = ST.get () in
  assert (B.as_seq h0 s.hmac_key == B.as_seq h1 s.hmac_key); // this is necessary for post-condition that represents key is not changed
  assert (B.as_seq h0 s.mmap == B.as_seq h1 s.mmap);
  ()

val attest_pke 
(ep_up: seL4_CPtr {I.sec_int_v ep_up >= 0}) 
: Stack unit 
(requires fun _ -> True)
(ensures fun h0 _ h1 -> ((B.as_seq h0 (st ()).sign_key) == (B.as_seq h1 (st ()).sign_key))  // key invariance
                        /\ ((B.as_seq h0 (st ()).mmap) == (B.as_seq h1 (st ()).mmap)) ) // mmap invariance

let attest_pke ep_up =
  let s = st () in
  recall_st_liveness s;
  let h0 = ST.get () in
  push_frame();
  // ** Getting sender_badge information by seL4_Recv (trick: use a pointer instead of giving the address of sender_badge variable)
  let sender_badge_ptr: B.pointer seL4_Word = B.alloca (u32 0) 1ul in
  let tag = seL4_Recv ep_up sender_badge_ptr in
  let sender_badge = B.index sender_badge_ptr 0ul in
  assert (B.(all_disjoint [loc_buffer sender_badge_ptr; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  // ** Getting challenge value (uint64) from the user process using seL4_GetMR
  let challenge_from_process: B.lbuffer seL4_Word 8 = B.alloca (u32 0) 8ul in    
  assert (B.(all_disjoint [loc_buffer challenge_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  B.upd challenge_from_process 0ul (seL4_GetMR (size 0));
  B.upd challenge_from_process 1ul (seL4_GetMR (size 1));
  B.upd challenge_from_process 2ul (seL4_GetMR (size 2));
  B.upd challenge_from_process 3ul (seL4_GetMR (size 3));
  B.upd challenge_from_process 4ul (seL4_GetMR (size 4));
  B.upd challenge_from_process 5ul (seL4_GetMR (size 5));
  B.upd challenge_from_process 6ul (seL4_GetMR (size 6));
  B.upd challenge_from_process 7ul (seL4_GetMR (size 7));
  let chal: buffer uint8 = create (size 32) (u8 0) in
  assert (B.(all_disjoint [loc_buffer chal; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  BB.uints_to_bytes_be #U32 #SEC (size 8) chal challenge_from_process; 
  assert (B.(all_disjoint [loc_buffer chal; loc_buffer challenge_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  let h = ST.get () in
  assert (B.live h chal); // this assertion is not necessary but it would reduce the runtime by helping the later assertion
  assert (B.as_seq h0 s.sign_key == B.as_seq h s.sign_key);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap);
  // ** Acknowledge the user process that we got the challenge
  seL4_SetMR (size 0) (u32 0);   
  seL4_Reply tag;
  // ** Again receiving the sender_badge information to get the public key of the user process
  let tag = seL4_Recv ep_up sender_badge_ptr in
  let sender_badge = B.index sender_badge_ptr 0ul in //update the sender_badge from sender_badge_ptr
  assert (B.(all_disjoint [loc_buffer sender_badge_ptr; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  // ** Getting public key (UInt64) from the user process using seL4_GetMR
  let pk_from_process: B.lbuffer seL4_Word 8 = B.alloca (u32 0) 8ul in 
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));  
  B.upd pk_from_process 0ul (seL4_GetMR (size 0));
  let h = ST.get () in
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  assert (B.as_seq h0 s.sign_key == B.as_seq h s.sign_key);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); 
  // assertion for seL4_GetMR correctness (without warning)
  let pk_from_process_0 = B.index pk_from_process 0ul in
  let ipc_buffer_msg_0 = B.index s.ipc_buffer.msg 0ul in
  assert (pk_from_process_0 == ipc_buffer_msg_0);
  B.upd pk_from_process 1ul (seL4_GetMR (size 1));
  let pk_from_process_1 = B.index pk_from_process 1ul in
  let ipc_buffer_msg_1 = B.index s.ipc_buffer.msg 1ul in
  assert (pk_from_process_1 == ipc_buffer_msg_1);
  B.upd pk_from_process 2ul (seL4_GetMR (size 2));
  let pk_from_process_2 = B.index pk_from_process 2ul in
  let ipc_buffer_msg_2 = B.index s.ipc_buffer.msg 2ul in
  assert (pk_from_process_2 == ipc_buffer_msg_2);
  B.upd pk_from_process 3ul (seL4_GetMR (size 3));
  let pk_from_process_3 = B.index pk_from_process 3ul in
  let ipc_buffer_msg_3 = B.index s.ipc_buffer.msg 3ul in
  assert (pk_from_process_3 == ipc_buffer_msg_3);
  B.upd pk_from_process 4ul (seL4_GetMR (size 4));
  let pk_from_process_4 = B.index pk_from_process 4ul in
  let ipc_buffer_msg_4 = B.index s.ipc_buffer.msg 4ul in
  assert (pk_from_process_4 == ipc_buffer_msg_4);
  B.upd pk_from_process 5ul (seL4_GetMR (size 5));
  let pk_from_process_5 = B.index pk_from_process 5ul in
  let ipc_buffer_msg_5 = B.index s.ipc_buffer.msg 5ul in
  assert (pk_from_process_5 == ipc_buffer_msg_5);
  B.upd pk_from_process 6ul (seL4_GetMR (size 6));
  let pk_from_process_6 = B.index pk_from_process 6ul in
  let ipc_buffer_msg_6 = B.index s.ipc_buffer.msg 6ul in
  assert (pk_from_process_6 == ipc_buffer_msg_6);
  B.upd pk_from_process 7ul (seL4_GetMR (size 7));
  let pk_from_process_7 = B.index pk_from_process 7ul in
  let ipc_buffer_msg_7 = B.index s.ipc_buffer.msg 7ul in
  assert (pk_from_process_7 == ipc_buffer_msg_7);
  let h = ST.get () in
  assert (B.live h chal); // this assertion is necessary
  assert (B.(all_disjoint [loc_buffer pk_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg; loc_buffer s.mmap]));
  assert (B.as_seq h0 s.sign_key == B.as_seq h s.sign_key);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); // this is necessary
  let pk: buffer uint8 = create (size 32) (u8 0) in
  BB.uints_to_bytes_be #U32 #SEC (size 8) pk pk_from_process;
  assert (B.(all_disjoint [loc_buffer pk; loc_buffer pk_from_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg]));
  // ** memcpy measurement from mmap to UInt8.t buffer (att_hash)
  let starting_point = (I.sec_int_v sender_badge) - (UInt64.v s.eP_UP_BADGE) in  
  let starting_point_uint32:UInt32.t = int_to_uint32 starting_point in
  recall_st_liveness s;
  let measurement_process = B.sub s.mmap starting_point_uint32 32ul in // subbuffer of mmap (UInt8.t buffer) starting from [sender_badge - EP_UP_BADGE] with length HMAC_OUTPUT_LEN (32ul)
  assert (B.(all_disjoint [loc_buffer measurement_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg]));
  // ** Sign the chal, pk, and measurement_process with the private key
  let h = ST.get () in 
  assert (B.live h chal /\ B.live h pk /\ B.live h measurement_process);
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap); // this is necessary
  // sign and hash result sizes are 32 bytes, assuming SHA2_256
  let sign_result_u8 : buffer uint8 = create (size 64) (u8 0) in // EdDSA signature length = 512 bits = 64 bytes
  let tmp_concat: buffer uint8 = create (size 96) (u8 0) in
  let tmp_hash: buffer uint8 = create (size (hash_length alg)) (u8 0) in
  assert (B.length s.sign_key == 32); // This is true and necessary for the next line
  test_concat_hash_and_sign_pke alg s.sign_key 32 chal 32 pk 32 measurement_process tmp_concat tmp_hash sign_result_u8;
  let h' = ST.get () in
  assert (B.(all_disjoint [loc_buffer sign_result_u8; loc_buffer tmp_concat; loc_buffer tmp_hash; loc_buffer chal; loc_buffer pk; loc_buffer measurement_process; loc_buffer s.sign_key; loc_buffer s.ipc_buffer.msg]));
  // assertion for functional correctness of "sign"
  assert (
          B.as_seq h' sign_result_u8 == 
            Spec.Ed25519.sign (B.as_seq h0 s.sign_key) 
              (Spec.Agile.Hash.hash alg 
                  (Lib.Sequence.concat #uint8 #64 #32 (Lib.Sequence.concat #uint8 #32 #32 (B.as_seq h chal) (B.as_seq h pk)) (B.as_seq h measurement_process)) 
              ) 
          );
  assert (B.as_seq h0 s.mmap == B.as_seq h' s.mmap); // this is necessary
  // // convert sign_result_u8 to sign_result_u64 (uint64 buffer) and send it to UP using seL4_SetMR and seL4_Reply
  // //convert uint8 to uint64
  // since the size of sign_result_u8 is 64 bytes, we need 8 seL4_SetMR calls to send it to UP
  let sign_result_u32: lbuffer uint32 (size 16) = create #uint32 (size 16) (u32 0) in
  BB.uints_from_bytes_be #U32 #SEC #(size 16) sign_result_u32 sign_result_u8; 
  assert (B.(all_disjoint [loc_buffer #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32; loc_buffer s.sign_key; loc_buffer s.mmap; loc_buffer s.ipc_buffer.msg]));
  let tmp_index_0 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 0ul in
  seL4_SetMR (size 0) tmp_index_0;
  let tmp_index_1 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 1ul in
  seL4_SetMR (size 1) tmp_index_1;
  let tmp_index_2 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 2ul in
  seL4_SetMR (size 2) tmp_index_2;
  let tmp_index_3 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 3ul in
  seL4_SetMR (size 3) tmp_index_3;
  let tmp_index_4 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 4ul in
  seL4_SetMR (size 4) tmp_index_4;
  let tmp_index_5 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 5ul in
  seL4_SetMR (size 5) tmp_index_5;
  let tmp_index_6 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 6ul in
  seL4_SetMR (size 6) tmp_index_6;
  let tmp_index_7 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 7ul in
  seL4_SetMR (size 7) tmp_index_7;
  let tmp_index_8 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 8ul in
  seL4_SetMR (size 8) tmp_index_8;
  let tmp_index_9 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 9ul in
  seL4_SetMR (size 9) tmp_index_9;
  let tmp_index_10 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 10ul in
  seL4_SetMR (size 10) tmp_index_10;
  let tmp_index_11 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 11ul in
  seL4_SetMR (size 11) tmp_index_11;
  let tmp_index_12 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 12ul in
  seL4_SetMR (size 12) tmp_index_12;
  let tmp_index_13 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 13ul in
  seL4_SetMR (size 13) tmp_index_13;
  let tmp_index_14 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 14ul in
  seL4_SetMR (size 14) tmp_index_14;
  let tmp_index_15 = B.index #uint32 #(B.trivial_preorder uint32) #(B.trivial_preorder uint32) sign_result_u32 15ul in
  seL4_SetMR (size 15) tmp_index_15;
  seL4_Reply tag;
  let h = ST.get () in
  assert (B.as_seq h0 s.mmap == B.as_seq h s.mmap);
  assert (B.as_seq h0 s.sign_key == B.as_seq h s.sign_key); 
  pop_frame();
  let h1 = ST.get () in
  assert (B.as_seq h0 s.sign_key == B.as_seq h1 s.sign_key); // this is necessary for post-condition that represents key is not changed
  assert (B.as_seq h0 s.mmap == B.as_seq h1 s.mmap);
  ()
