API ?= 35
PROJECT ?= PD2339-BP2A.250605.031.A3
OUTDIR ?= build/$(PROJECT)/bin
EMBEDDIR ?= build/embed

TARGET_DIR := src/targets
TARGET_HEADER := $(TARGET_DIR)/target.h

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error missing $(TARGET_HEADER))
endif

define pick_src
$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))
endef

EMBED_SU := $(EMBEDDIR)/su_daemon_aarch64_pie
PRELOAD := $(OUTDIR)/preload.so

CORE_SRCS := \
  $(call pick_src,main.c) \
  $(call pick_src,util.c) \
  $(call pick_src,slide.c) \
  $(call pick_src,fops.c) \
  $(call pick_src,pipe.c) \
  src/chain.c \
  src/root.c
PRELOAD_SRCS := $(CORE_SRCS) src/preload.c src/su_blob.S
SUKSU := $(OUTDIR)/su_ksu

.DEFAULT_GOAL := all

NDK_CANDIDATES := $(ANDROID_NDK_HOME) $(ANDROID_NDK_ROOT) \
                  $(wildcard $(HOME)/android-ndk-cache/android-ndk-*) \
                  $(wildcard $(HOME)/Android/Sdk/ndk/*) \
                  /opt/android-ndk
NDK_TOOLCHAIN ?= $(firstword $(foreach n,$(NDK_CANDIDATES),\
                            $(wildcard $(n)/toolchains/llvm/prebuilt/linux-x86_64)))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(firstword $(wildcard $(NDK_TOOLCHAIN)/lib/clang/*))

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none
HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android
HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_COMMON_LDFLAGS :=
    TARGET_PIE_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
    TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"targets/target.h\"

GL_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_CFLAGS := -DBUILD_VERSION=\"$(GL_VERSION)\"

# 用递归$(MAKE)串行串联，不用依赖项——依赖项不保证顺序，make -j下会竞态
.PHONY: all preload su_ksu clean info install tools payload psl2 distclean

all:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory tools
	@$(MAKE) --no-print-directory payload
	@echo
	@echo "=== build complete (version=$(GL_VERSION)) ==="

tools:
	@$(MAKE) -C tools

psl2: tools

payload: preload su_ksu
	@mkdir -p payloads
	@cp -f $(PRELOAD) payloads/preload.so
	@echo "installed payloads/preload.so  version=$(GL_VERSION)  $$(sha256sum payloads/preload.so | cut -c1-16)"

preload: $(PRELOAD)

# install是payload的别名，保留以免打断既有脚本
install: payload

$(SUKSU): src/su_ksu.c | $(OUTDIR)
	$(TARGET_CC) -Os -static -nostdlib -ffreestanding -fno-builtin \
	  -fno-stack-protector -fno-asynchronous-unwind-tables \
	  -fno-unwind-tables -ffunction-sections -fdata-sections \
	  -Wl,--build-id=none -Wl,--gc-sections -Wl,-z,noseparate-code \
	  -Wall -Wextra -Wno-unused-parameter -o $@ $<

su_ksu: $(SUKSU)

$(OUTDIR):
	mkdir -p $@

$(EMBEDDIR):
	mkdir -p $@

$(EMBED_SU): src/su_daemon.c | $(EMBEDDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) $(TARGET_CFLAGS) $(VERSION_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) $(wildcard src/*.h) $(wildcard src/kernelsnitch/*.h) | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) $(VERSION_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	sha256sum $@

info:
	@echo "PROJECT=$(PROJECT)"
	@echo "TARGET_DIR=$(TARGET_DIR)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "EMBED_SU=$(EMBED_SU)"
	@echo "CORE_SRCS=$(CORE_SRCS)"

	@echo "GL_VERSION=$(GL_VERSION)"

clean:
	rm -rf build payloads
	@$(MAKE) --no-print-directory -C tools clean

# 语义别名，clean已涵盖全部产物
distclean: clean