ifeq (,$(FSTAR_HOME))
  $(error FSTAR_HOME is not defined)
endif

ifeq (,$(KRML_HOME))
  $(error KRML_HOME is not defined)
endif

ifeq (,$(HACL_HOME))
  $(error HACL_HOME is not defined)
endif

include ../Makefile.include

#for getting macros for OCaml commands to compile extracted code
include $(FSTAR_ULIB)/ml/Makefile.include

include $(HACL_HOME)/Makefile.include
include $(HACL_HOME)/Makefile.common

# The paths to related files which to include for scanning
#   -- No need to add FSTAR_HOME/ulib; it is included by default
INCLUDE_PATHS ?=

# The executable file you want to produce
PROGRAM = lowToC

# A place to put all the emitted .ml files
OUT_DIR = ./obj

# A place to put all the .checked files
CACHE_DIR = ./obj

# A place to pull all the .hints files
HINT_DIR = ./hints

# Main entry points (first one is default)
# -----------------------------------------
all: dist/$(PROGRAM).a

# ------------------------------------
# The root files of your project, from which to begin scanning dependences
FSTAR_FILES = $(wildcard code/*.fst) $(wildcard code/*.fsti)

# Set up F* flags
# ----------------
LOWTOC_HOME ?= $(realpath .)
SOURCE_DIRS = $(LOWTOC_HOME)/code

INCLUDE_DIRS = \
	$(SOURCE_DIRS) \
	$(KRML_HOME)/krmllib \
	$(KRML_HOME)/krmllib/obj \
	$(ALL_HACL_DIRS)

FSTAR_INCLUDES = $(addprefix --include ,$(INCLUDE_DIRS))

# FSTAR_ALREADY_CACHED = --already_cached 'Prims FStar LowStar Lib Spec EverCrypt Vale C'

FSTAR_FLAGS = $(FSTAR_INCLUDES) \
  --cache_checked_modules \
  --cache_dir $(CACHE_DIR) \
  --odir $(OUT_DIR) \
  --cmi \
  --use_hints \
  --record_hints \
  --already_cached '*,-Hello'\
  --warn_error @241-274 \
   

# FSTAR_HINTS ?= --use_hints --use_hint_hashes --record_hints
# FSTAR_EXTRACT = --extract 'OCaml:-* +Spec'

FSTAR = $(FSTAR_HOME)/bin/fstar.exe $(FSTAR_FLAGS)

ifndef NODEPEND
ifndef MAKE_RESTARTS
.depend: .FORCE
	mkdir -p obj
	$(FSTAR) --dep full $(FSTAR_FILES) > $@

.PHONY: .FORCE
.FORCE:
endif
endif

.PHONY: clean
clean:
	rm -rf obj dist hints .depend *.exe

include .depend


# Verification
#--------------
output:
	mkdir -p hints
	mkdir -p obj

# %.checked: FSTAR_FLAGS=
# %.checked: | hints obj
# 	$(FSTAR) $< $(FSTAR_FLAGS) && touch -c $@
obj/%.checked: output code/%
	$(FSTAR) --hint_file hints/$(notdir $*).hints $(notdir $*) && touch -c $@

# Extraction
#------------
# .PRECIOUS: obj/%.ml 
# obj/%.ml: .cache/%.fst.checked
# 	$(FSTAR) $(FSTAR_EXTRACT_FLAGS) --codegen OCaml \
# 	--extract_module $(basename $(notdir $@)) code/$(basename $(notdir $@)).fst

.PRECIOUS: obj/%.krml
obj/%.krml: 
	$(FSTAR) --codegen krml \
	--extract_module $(basename $(notdir $(subst .checked,,$<))) \
	$(notdir $(subst .checked,,$<))
  
# F* --> C
# --------
KRML=$(KRML_HOME)/krml

ARCH=x86
SEL4_TUT_DIR=/home/seoyeon/workspace/sel4-tutorials-manifest
SEL4_LIBS=$(SEL4_TUT_DIR)/projects/seL4_libs
SEL4_PATHs=-add-include '"vspace/vspace.h"'
SEL4_BUILD_DIR=dynamic-3_build

# Making sure that the extern symbols generated in MerkleTree_EverCrypt
# correspond to the ones found in libevercrypt.so
VALE_FLAGS= \
  -library 'Vale.Stdcalls.*' \
  -no-prefix 'Vale.Stdcalls.*' \
  -static-header 'Vale.Inline.*' \
  -library 'Vale.Inline.X64.Fadd_inline' \
  -library 'Vale.Inline.X64.Fmul_inline' \
  -library 'Vale.Inline.X64.Fswap_inline' \
  -library 'Vale.Inline.X64.Fsqr_inline' \
  -no-prefix 'Vale.Inline.X64.Fadd_inline' \
  -no-prefix 'Vale.Inline.X64.Fmul_inline' \
  -no-prefix 'Vale.Inline.X64.Fswap_inline' \
  -no-prefix 'Vale.Inline.X64.Fsqr_inline' \

dist/Makefile.basic:  $(filter-out %prims.krml,$(ALL_KRML_FILES))
	$(KRML) $^ -tmpdir $(dir $@) -skip-compilation \
		-minimal \
		-add-include '"krml/internal/target.h"' \
	  	-add-include '"krml/internal/types.h"' \
	  	-add-include '"krml/lowstar_endianness.h"' \
	  	-add-include '<stdint.h>' \
	  	-add-include '<stdbool.h>' \
	  	-add-include '<string.h>' \
	  	-fparentheses \
		-o $(PROGRAM).a \
		$(VALE_FLAGS) \
		-no-prefix 'Hello' \
		-bundle EverCrypt.Hash=EverCrypt,EverCrypt.*,Meta.*,Hacl.*,Vale.*,Spec.*,Lib.* \
		-library EverCrypt.AutoConfig2 \
		-bundle LowStar.* \
		-bundle Prims,C.Failure,C,C.String,C.Loops,Spec.Loops,C.Endianness,FStar.*[rename=lowToC_Krmllib] \
		-library 'Meta.*,Hacl.*,Vale.*,Spec.*,Lib.*' \
		-ccopts '-DLib_IntVector_Intrinsics_vec256=void*,-DLib_IntVector_Intrinsics_vec128=void*'
  
# sed -i '36i typedef uint8_t Lib_IntTypes_uint1;' $(OUT_DIR)/EverCrypt_HMAC.h 

# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/seL4_libs/libsel4utils/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/autoconf' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/kernel/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/include' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/arch_include/x86' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/sel4_arch_include/x86_64' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/autoconf' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/kernel/gen_config' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/libsel4/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/musllibc/build-temp/stage/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/util_libs/libutils/gen_config' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/seL4_libs/libsel4vka/gen_config' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/seL4_libs/libsel4utils/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/util_libs/libplatsupport/gen_config' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/seL4_libs/libsel4muslcsys/gen_config' $(OUT_DIR)/Makefile.basic 
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/$(SEL4_BUILD_DIR)/sel4runtime/gen_config' $(OUT_DIR)/Makefile.basic 

# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/dynamic-3/hacl-star/dist/gcc64-only' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/dynamic-3/hacl-star/dist/kremlin/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/dynamic-3/hacl-star/dist/kremlin/kremlib/dist/minimal' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/sel4runtime/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/sel4runtime/include/mode/64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/sel4runtime/include/arch/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/sel4runtime/include/sel4_arch/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/kernel/libsel4/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/kernel/libsel4/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/kernel/libsel4/sel4_arch_include/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/kernel/libsel4/sel4_plat_include/pc99' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/kernel/libsel4/mode_include/64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libutils/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libutils/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/sel4-tutorials/libsel4tutorials/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4platsupport/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4platsupport/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4platsupport/plat_include/pc99' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4simple/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4simple/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vka/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vka/sel4_arch_include/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vka/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4debug/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4debug/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4debug/sel4_arch_include/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vspace/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vspace/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libplatsupport/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libplatsupport/plat_include/pc99' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libplatsupport/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libfdt/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libfdt/.' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4simple-default/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4muslcsys/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libcpio/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4utils/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4utils/sel4_arch_include/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4utils/arch_include/x86' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_TUT_DIR)/projects/util_libs/libelf/includ' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4allocman/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4allocman/sel4_arch/x86_64' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4allocman/arch/x86' $(OUT_DIR)/Makefile.basic

# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vspace/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4allocman/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4bench/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4debug/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4muslcsys/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4platsupport/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4serialserver/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4simple/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4simple-default/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4sync/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4test/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4utils/include' $(OUT_DIR)/Makefile.basic
# sed -i '14i CFLAGS += -I $(SEL4_LIBS)/libsel4vka/include' $(OUT_DIR)/Makefile.basic

# Compiling the generated C code`
# ------------------------------
dist/$(PROGRAM).a: dist/Makefile.basic 
	@echo "KRML done. Check the generated C files in $(dir $@)." 
#	$(MAKE) -C $(dir $@) -f $(notdir $<)  


