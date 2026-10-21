API ?= 35
PROJECT ?= PD2339-BP2A.250605.031.A3
OUTDIR ?= build/$(PROJECT)/bin
EMBEDDIR ?= build/embed

TARGET_DIR := src/targets
TARGET_HEADER := $(TARGET_DIR)/target.h

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error missing $(TARGET_HEADER))
endif

ifeq ($(OS),Windows_NT)
  SHELL := cmd.exe
  .SHELLFLAGS := /c
  DEVNULL := NUL
  EXIT_FAIL = exit /b 1
  WINPATH = $(subst /,\,$(1))
  MKDIR = if not exist "$(call WINPATH,$(1))" mkdir "$(call WINPATH,$(1))" || $(EXIT_FAIL)
  COPY = copy /y "$(call WINPATH,$(1))" "$(call WINPATH,$(2))" > $(DEVNULL) || $(EXIT_FAIL)
  RM_RF = if exist "$(call WINPATH,$(1))" rmdir /s /q "$(call WINPATH,$(1))" || $(EXIT_FAIL)
  RM_F = if exist "$(call WINPATH,$(1))" del /f /q "$(call WINPATH,$(1))" || $(EXIT_FAIL)
  HASH_FULL = powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '$(call WINPATH,$(1))').Hash"
  HASH_SHORT = powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '$(call WINPATH,$(1))').Hash.Substring(0,16)"
  SHA256 = $(call HASH_SHORT,$(1))
  SHA256_FULL = @echo $(call HASH_SHORT,$(1))  $(1)
  HOST_KIND := windows
  NDK_HOSTS := windows-x86_64
else
  DEVNULL := /dev/null
  MKDIR = mkdir -p $(1)
  COPY = cp -f $(1) $(2)
  RM_RF = rm -rf $(1)
  RM_F = rm -f $(1)
  SHA256 = sha256sum $(1) | cut -c1-16
  SHA256_FULL = sha256sum $(1)
  HOST_KIND := posix
  NDK_HOSTS := linux-x86_64
endif

NDK_HOST := $(firstword $(NDK_HOSTS))
define NDK_ERR_NO_NDK
ERROR: Android NDK not found.
  Searched: ANDROID_NDK_HOME, ANDROID_NDK_ROOT,
            HOME/android-ndk-cache/android-ndk-*, HOME/Android/Sdk/ndk/*,
            LOCALAPPDATA/Android/Sdk/ndk/*, /opt/android-ndk
  Next step: set ANDROID_NDK_HOME to an Android NDK r30 or newer, e.g.
            set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
  Or point the build at it explicitly:
            make NDK_TOOLCHAIN=<ndk>/toolchains/llvm/prebuilt/$(NDK_HOST)
endef

define NDK_ERR_NO_WRAPPER
ERROR: NDK found at $(NDK_TOOLCHAIN) but it has no aarch64-linux-android$(API)-clang wrapper.
  That wrapper is missing on NDK releases older than r30. Next step: install a
  newer Android NDK and set ANDROID_NDK_HOME to it, e.g.
            set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
endef

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

NDK_ENV_HOME := $(subst \,/,$(ANDROID_NDK_HOME))
NDK_ENV_ROOT := $(subst \,/,$(ANDROID_NDK_ROOT))
NDK_WIN_SDK  := $(wildcard $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*)
NDK_POSIX_SDK := $(wildcard $(HOME)/Android/Sdk/ndk/*)
NDK_POSIX_CACHE := $(wildcard $(HOME)/android-ndk-cache/android-ndk-*)

NDK_CANDIDATES := $(NDK_ENV_HOME) $(NDK_ENV_ROOT) \
                  $(NDK_POSIX_CACHE) \
                  $(NDK_POSIX_SDK) \
                  $(NDK_WIN_SDK) \
                  /opt/android-ndk
NDK_TOOLCHAIN ?= $(firstword $(foreach n,$(NDK_CANDIDATES),\
                            $(wildcard $(n)/toolchains/llvm/prebuilt/$(NDK_HOST))))
NDK_CC_BASE := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
# The Windows NDK ships per-API wrappers as .cmd batch files; POSIX has plain
# executables. Take whichever of the three spellings actually exists.
NDK_CC := $(firstword $(wildcard $(NDK_CC_BASE).cmd) \
                       $(wildcard $(NDK_CC_BASE).exe) \
                       $(wildcard $(NDK_CC_BASE)))
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

ifeq ($(NDK_TOOLCHAIN),)
  NDK_STATE := missing
else ifeq ($(NDK_CC),)
  NDK_STATE := no-wrapper
else
  NDK_STATE := ok
endif

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifeq ($(NDK_STATE),ok)
  NDK_CC_WORKS := $(if $(shell "$(NDK_CC)" --version 2>$(DEVNULL)),yes,)
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

GL_VERSION ?= $(or $(shell git describe --tags --always --dirty 2>$(DEVNULL)),dev)
VERSION_CFLAGS := -DBUILD_VERSION=\"$(GL_VERSION)\"

.PHONY: all preload su_ksu clean info install tools payload psl2 distclean check-ndk

check-ndk:
	@$(if $(filter missing,$(NDK_STATE)),$(error $(NDK_ERR_NO_NDK)))
	@$(if $(filter no-wrapper,$(NDK_STATE)),$(error $(NDK_ERR_NO_WRAPPER)))

all:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory tools
	@$(MAKE) --no-print-directory payload
	@echo
	@echo "=== build complete (version=$(GL_VERSION)) ==="

tools:
	@$(MAKE) -C tools

psl2: tools

payload: preload su_ksu | check-ndk
	@$(call MKDIR,payloads)
	@$(call COPY,$(PRELOAD),payloads/preload.so)
	@echo "installed payloads/preload.so  version=$(GL_VERSION)  $(call SHA256,payloads/preload.so)"

preload: $(PRELOAD)

install: payload

$(SUKSU): src/su_ksu.c | $(OUTDIR) check-ndk
	"$(TARGET_CC)" -Os -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections -Wl,--build-id=none -Wl,--gc-sections -Wl,-z,noseparate-code -Wall -Wextra -Wno-unused-parameter -o $@ $<

su_ksu: $(SUKSU)

$(OUTDIR):
	@$(call MKDIR,$@)

$(EMBEDDIR):
	@$(call MKDIR,$@)

$(EMBED_SU): src/su_daemon.c | $(EMBEDDIR) check-ndk
	"$(TARGET_CC)" $(TARGET_FLAGS) $(PIE_CFLAGS) $(TARGET_CFLAGS) $(VERSION_CFLAGS) $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) $(wildcard src/*.h) $(wildcard src/kernelsnitch/*.h) | $(OUTDIR) check-ndk
	"$(TARGET_CC)" $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) $(VERSION_CFLAGS) $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) -shared -o $@ -pthread
	$(call SHA256_FULL,$@)

info: | check-ndk
	@echo "PROJECT=$(PROJECT)"
	@echo "TARGET_DIR=$(TARGET_DIR)"
	@echo "HOST_KIND=$(HOST_KIND)"
	@echo "HOST=$(NDK_HOST)"
	@echo "NDK_TOOLCHAIN=$(NDK_TOOLCHAIN)"
	@echo "NDK_CC=$(NDK_CC)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "EMBED_SU=$(EMBED_SU)"
	@echo "CORE_SRCS=$(CORE_SRCS)"
	@echo "GL_VERSION=$(GL_VERSION)"

clean:
	@$(call RM_RF,build)
	@$(call RM_RF,payloads)
	@$(MAKE) --no-print-directory -C tools clean

distclean: clean