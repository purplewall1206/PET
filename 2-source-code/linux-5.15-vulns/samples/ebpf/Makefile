# SPDX-License-Identifier: GPL-2.0

BPF_SAMPLES_PATH ?= $(abspath $(srctree)/$(src))
TOOLS_PATH := $(BPF_SAMPLES_PATH)/../../tools

# List of programs to build


# tprogs-y += unittest
# tprogs-y += kmalloc_ret
# tprogs-y += cf_track
# tprogs-y += kmalloc_branch
tprogs-y += detector_CVE-2010-2959
tprogs-y += detector_CVE-2016-6187
tprogs-y += detector_CVE-2017-7308
tprogs-y += detector_CVE-2017-7184
tprogs-y += detector_CVE-2022-1015
tprogs-y += detector_CVE-2022-34918
tprogs-y += detector_CVE-2020-14386
tprogs-y += detector_CVE-2021-22555
tprogs-y += detector_CVE-2022-27666
# tprogs-y += detector_CVE-2022-0435
tprogs-y += detector_CVE-2021-43276
tprogs-y += detector_SYZ-a770bf515613
tprogs-y += detector_CTF-hxp2020
tprogs-y += detector_CVE-2017-18344
tprogs-y += detector_CVE-2022-0382
tprogs-y += detector_CVE-2021-34693
tprogs-y += detector_SYZ-cd443f1e91ca
tprogs-y += detector_uaf
tprogs-y += detector_CVE-2022-2586
tprogs-y += detector_CVE-2022-2588
tprogs-y += detector_CVE-2021-3715



# Libbpf dependencies
LIBBPF = $(TOOLS_PATH)/lib/bpf/libbpf.a

CGROUP_HELPERS := ../../tools/testing/selftests/bpf/cgroup_helpers.o
TRACE_HELPERS := ../../tools/testing/selftests/bpf/trace_helpers.o


# unittest-objs := unittest.o
# kmalloc_ret-objs := kmalloc_ret.o
# cf_track-objs := cf_track.o
# kmalloc_branch-objs := kmalloc_branch.o
detector_CVE-2010-2959-objs := detector_CVE-2010-2959.o
detector_CVE-2016-6187-objs := detector_CVE-2016-6187.o
detector_CVE-2017-7308-objs := detector_CVE-2017-7308.o
detector_CVE-2017-7184-objs := detector_CVE-2017-7184.o
detector_CVE-2022-1015-objs := detector_CVE-2022-1015.o
detector_CVE-2022-34918-objs := detector_CVE-2022-34918.o
detector_CVE-2020-14386-objs := detector_CVE-2020-14386.o
detector_CVE-2021-22555-objs := detector_CVE-2021-22555.o
detector_CVE-2022-27666-objs := detector_CVE-2022-27666.o
# detector_CVE-2022-0435-objs := detector_CVE-2022-0435.o
detector_CVE-2021-43276-objs := detector_CVE-2021-43276.o
detector_SYZ-a770bf515613-objs := detector_SYZ-a770bf515613.o
detector_CTF-hxp2020-objs := detector_CTF-hxp2020.o
detector_CVE-2017-18344-objs := detector_CVE-2017-18344.o
detector_CVE-2022-0382-objs := detector_CVE-2022-0382.o
detector_CVE-2021-34693-objs := detector_CVE-2021-34693.o
detector_SYZ-cd443f1e91ca-objs := detector_SYZ-cd443f1e91ca.o
detector_uaf-objs := detector_uaf.o
detector_CVE-2022-2586-objs := detector_CVE-2022-2586.o
detector_CVE-2022-2588-objs := detector_CVE-2022-2588.o
detector_CVE-2021-3715-objs := detector_CVE-2021-3715.o


# Tell kbuild to always build the programs
always-y := $(tprogs-y)


# always-y += unittest.bpf.o
# always-y += kmalloc_ret.bpf.o
# always-y += cf_track.bpf.o
# always-y += kmalloc_branch.bpf.o
always-y += detector_CVE-2010-2959.bpf.o
always-y += detector_CVE-2016-6187.bpf.o
always-y += detector_CVE-2017-7308.bpf.o
always-y += detector_CVE-2017-7184.bpf.o
always-y += detector_CVE-2022-1015.bpf.o
always-y += detector_CVE-2022-34918.bpf.o
always-y += detector_CVE-2020-14386.bpf.o
always-y += detector_CVE-2021-22555.bpf.o
always-y += detector_CVE-2022-27666.bpf.o
# always-y += detector_CVE-2022-0435.bpf.o
always-y += detector_CVE-2021-43276.bpf.o
always-y += detector_SYZ-a770bf515613.bpf.o
always-y += detector_CTF-hxp2020.bpf.o
always-y += detector_CVE-2017-18344.bpf.o
always-y += detector_CVE-2022-0382.bpf.o
always-y += detector_CVE-2021-34693.bpf.o
always-y += detector_SYZ-cd443f1e91ca.bpf.o
always-y += detector_uaf.bpf.o
always-y += detector_CVE-2022-2586.bpf.o
always-y += detector_CVE-2022-2588.bpf.o
always-y += detector_CVE-2021-3715.bpf.o


ifeq ($(ARCH), arm)
# Strip all except -D__LINUX_ARM_ARCH__ option needed to handle linux
# headers when arm instruction set identification is requested.
ARM_ARCH_SELECTOR := $(filter -D__LINUX_ARM_ARCH__%, $(KBUILD_CFLAGS))
BPF_EXTRA_CFLAGS := $(ARM_ARCH_SELECTOR)
TPROGS_CFLAGS += $(ARM_ARCH_SELECTOR)
endif

ifeq ($(ARCH), mips)
TPROGS_CFLAGS += -D__SANE_USERSPACE_TYPES__
ifdef CONFIG_MACH_LOONGSON64
BPF_EXTRA_CFLAGS += -I$(srctree)/arch/mips/include/asm/mach-loongson64
BPF_EXTRA_CFLAGS += -I$(srctree)/arch/mips/include/asm/mach-generic
endif
endif

TPROGS_CFLAGS += -Wall -O2
TPROGS_CFLAGS += -Wmissing-prototypes
TPROGS_CFLAGS += -Wstrict-prototypes

TPROGS_CFLAGS += -I$(objtree)/usr/include
TPROGS_CFLAGS += -I$(srctree)/tools/testing/selftests/bpf/
TPROGS_CFLAGS += -I$(srctree)/tools/lib/
TPROGS_CFLAGS += -I$(srctree)/tools/include
TPROGS_CFLAGS += -I$(srctree)/tools/perf
TPROGS_CFLAGS += -DHAVE_ATTR_TEST=0

ifdef SYSROOT
TPROGS_CFLAGS += --sysroot=$(SYSROOT)
TPROGS_LDFLAGS := -L$(SYSROOT)/usr/lib
endif

TPROGS_LDLIBS			+= $(LIBBPF) -lelf -lz
TPROGLDLIBS_tracex4		+= -lrt
TPROGLDLIBS_trace_output	+= -lrt
TPROGLDLIBS_map_perf_test	+= -lrt
TPROGLDLIBS_test_overhead	+= -lrt
TPROGLDLIBS_xdpsock		+= -pthread -lcap
TPROGLDLIBS_xsk_fwd		+= -pthread

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
# make M=samples/bpf LLC=~/git/llvm-project/llvm/build/bin/llc CLANG=~/git/llvm-project/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
OPT ?= opt
LLVM_DIS ?= llvm-dis
LLVM_OBJCOPY ?= llvm-objcopy
BTF_PAHOLE ?= pahole

# Detect that we're cross compiling and use the cross compiler
ifdef CROSS_COMPILE
CLANG_ARCH_ARGS = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

# Don't evaluate probes and warnings if we need to run make recursively
ifneq ($(src),)
HDR_PROBE := $(shell printf "\#include <linux/types.h>\n struct list_head { int a; }; int main() { return 0; }" | \
	$(CC) $(TPROGS_CFLAGS) $(TPROGS_LDFLAGS) -x c - \
	-o /dev/null 2>/dev/null && echo okay)

ifeq ($(HDR_PROBE),)
$(warning WARNING: Detected possible issues with include path.)
$(warning WARNING: Please install kernel headers locally (make headers_install).)
endif

BTF_LLC_PROBE := $(shell $(LLC) -march=bpf -mattr=help 2>&1 | grep dwarfris)
BTF_PAHOLE_PROBE := $(shell $(BTF_PAHOLE) --help 2>&1 | grep BTF)
BTF_OBJCOPY_PROBE := $(shell $(LLVM_OBJCOPY) --help 2>&1 | grep -i 'usage.*llvm')
BTF_LLVM_PROBE := $(shell echo "int main() { return 0; }" | \
			  $(CLANG) -target bpf -O2 -g -c -x c - -o ./llvm_btf_verify.o; \
			  readelf -S ./llvm_btf_verify.o | grep BTF; \
			  /bin/rm -f ./llvm_btf_verify.o)

BPF_EXTRA_CFLAGS += -fno-stack-protector
ifneq ($(BTF_LLVM_PROBE),)
	BPF_EXTRA_CFLAGS += -g
else
ifneq ($(and $(BTF_LLC_PROBE),$(BTF_PAHOLE_PROBE),$(BTF_OBJCOPY_PROBE)),)
	BPF_EXTRA_CFLAGS += -g
	LLC_FLAGS += -mattr=dwarfris
	DWARF2BTF = y
endif
endif
endif

# Trick to allow make to be run from this directory
all:
	$(MAKE) -C ../../ M=$(CURDIR) BPF_SAMPLES_PATH=$(CURDIR)

clean:
	$(MAKE) -C ../../ M=$(CURDIR) clean
	@find $(CURDIR) -type f -name '*~' -delete

$(LIBBPF): FORCE
# Fix up variables inherited from Kbuild that tools/ build system won't like
	$(MAKE) -C $(dir $@) RM='rm -rf' EXTRA_CFLAGS="$(TPROGS_CFLAGS)" \
		LDFLAGS=$(TPROGS_LDFLAGS) srctree=$(BPF_SAMPLES_PATH)/../../ O=

BPFTOOLDIR := $(TOOLS_PATH)/bpf/bpftool
BPFTOOL := $(BPFTOOLDIR)/bpftool
$(BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile)
	    $(MAKE) -C $(BPFTOOLDIR) srctree=$(BPF_SAMPLES_PATH)/../../

$(obj)/syscall_nrs.h:	$(obj)/syscall_nrs.s FORCE
	$(call filechk,offsets,__SYSCALL_NRS_H__)

targets += syscall_nrs.s
clean-files += syscall_nrs.h

FORCE:


# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(BPF_SAMPLES_PATH)/*.c: verify_target_bpf $(LIBBPF)
$(src)/*.c: verify_target_bpf $(LIBBPF)



-include $(BPF_SAMPLES_PATH)/Makefile.target

VMLINUX_BTF_PATHS ?= $(abspath $(if $(O),$(O)/vmlinux))				\
		     $(abspath $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux))	\
		     $(abspath ./vmlinux)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))

$(obj)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL)
ifeq ($(VMLINUX_H),)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(Q)cp "$(VMLINUX_H)" $@
endif

ifeq ($(VMLINUX_BTF),)
	$(error Cannot find a vmlinux for VMLINUX_BTF at any of "$(VMLINUX_BTF_PATHS)",\
		build the kernel or set VMLINUX_BTF variable)
endif

clean-files += vmlinux.h

# Get Clang's default includes on this system, as opposed to those seen by
# '-target bpf'. This fixes "missing" files on some architectures/distros,
# such as asm/byteorder.h, asm/socket.h, asm/sockios.h, sys/cdefs.h etc.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
define get_sys_includes
$(shell $(1) -v -E - </dev/null 2>&1 \
        | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') \
$(shell $(1) -dM -E - </dev/null | grep '#define __riscv_xlen ' | sed 's/#define /-D/' | sed 's/ /=/')
endef

CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG))

$(obj)/%.bpf.o: $(src)/%.bpf.c $(obj)/vmlinux.h $(src)/xdp_sample.bpf.h $(src)/xdp_sample_shared.h
	@echo "  CLANG-BPF " $@
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(SRCARCH) \
		-Wno-compare-distinct-pointer-types -I$(srctree)/include \
		-I$(srctree)/samples/bpf -I$(srctree)/tools/include \
		-I$(srctree)/tools/lib $(CLANG_SYS_INCLUDES) \
		-c $(filter %.bpf.c,$^) -o $@

# LINKED_SKELS := xdp_redirect_cpu.skel.h xdp_redirect_map_multi.skel.h \
# 		xdp_redirect_map.skel.h xdp_redirect.skel.h xdp_monitor.skel.h
clean-files += $(LINKED_SKELS)


LINKED_BPF_SRCS := $(patsubst %.bpf.o,%.bpf.c,$(foreach skel,$(LINKED_SKELS),$($(skel)-deps)))

BPF_SRCS_LINKED := $(notdir $(wildcard $(src)/*.bpf.c))
BPF_OBJS_LINKED := $(patsubst %.bpf.c,$(obj)/%.bpf.o, $(BPF_SRCS_LINKED))
BPF_SKELS_LINKED := $(addprefix $(obj)/,$(LINKED_SKELS))

$(BPF_SKELS_LINKED): $(BPF_OBJS_LINKED) $(BPFTOOL)
	@echo "  BPF GEN-OBJ " $(@:.skel.h=)
	$(Q)$(BPFTOOL) gen object $(@:.skel.h=.lbpf.o) $(addprefix $(obj)/,$($(@F)-deps))
	@echo "  BPF GEN-SKEL" $(@:.skel.h=)
	$(Q)$(BPFTOOL) gen skeleton $(@:.skel.h=.lbpf.o) name $(notdir $(@:.skel.h=)) > $@

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
# below we use long chain of commands, clang | opt | llvm-dis | llc,
# to generate final object file. 'clang' compiles the source into IR
# with native target, e.g., x64, arm64, etc. 'opt' does bpf CORE IR builtin
# processing (llvm12) and IR optimizations. 'llvm-dis' converts
# 'opt' output to IR, and finally 'llc' generates bpf byte code.
$(obj)/%.o: $(src)/%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(BPF_EXTRA_CFLAGS) \
		-I$(obj) -I$(srctree)/tools/testing/selftests/bpf/ \
		-I$(srctree)/tools/lib/ \
		-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(SRCARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-fno-asynchronous-unwind-tables \
		-I$(srctree)/samples/bpf/ -include asm_goto_workaround.h \
		-O2 -emit-llvm -Xclang -disable-llvm-passes -c $< -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@
ifeq ($(DWARF2BTF),y)
	$(BTF_PAHOLE) -J $@
endif
