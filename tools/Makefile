API      ?= 35
PSL2_API ?= 37

ifeq ($(OS),Windows_NT)
  SHELL := cmd.exe
  .SHELLFLAGS := /c
  DEVNULL := NUL
  WINPATH = $(subst /,\,$(1))
  RM_F = if exist "$(call WINPATH,$(1))" del /f /q "$(call WINPATH,$(1))" || exit /b 1
  HOST_KIND := windows
  NDK_HOSTS := windows-x86_64
else
  RM_F = rm -f $(1)
  HOST_KIND := posix
  NDK_HOSTS := linux-x86_64
endif

NDK_HOST := $(firstword $(NDK_HOSTS))

NDK_ENV_HOME := $(subst \,/,$(ANDROID_NDK_HOME))
NDK_ENV_ROOT := $(subst \,/,$(ANDROID_NDK_ROOT))
NDK_WIN_SDK  := $(wildcard $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*)

NDK_CANDIDATES := $(NDK_ENV_HOME) $(NDK_ENV_ROOT) \
                  $(wildcard $(HOME)/android-ndk-cache/android-ndk-*) \
                  $(wildcard $(HOME)/Android/Sdk/ndk/*) \
                  $(NDK_WIN_SDK) \
                  /opt/android-ndk
NDK_TOOLCHAIN ?= $(firstword $(foreach n,$(NDK_CANDIDATES),\
                     $(wildcard $(n)/toolchains/llvm/prebuilt/$(NDK_HOST))))

CC_BASE      := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
CC      := $(firstword $(wildcard $(CC_BASE).cmd) \
                       $(wildcard $(CC_BASE).exe) \
                       $(wildcard $(CC_BASE)))
PSL2_CC_BASE := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(PSL2_API)-clang
PSL2_CC := $(firstword $(wildcard $(PSL2_CC_BASE).cmd) \
                       $(wildcard $(PSL2_CC_BASE).exe) \
                       $(wildcard $(PSL2_CC_BASE)))

HOSTED_CFLAGS := -static -O2

BINS := hijtest slot_restore psl2 bandscan

.PHONY: all clean check-ndk check-psl2-cc $(BINS)

all: hijtest slot_restore psl2 bandscan

define ERR_NO_NDK
ERROR: Android NDK not found (need an aarch64-linux-android$(API) wrapper).
  Searched: ANDROID_NDK_HOME, ANDROID_NDK_ROOT,
            HOME/android-ndk-cache/android-ndk-*, HOME/Android/Sdk/ndk/*,
            LOCALAPPDATA/Android/Sdk/ndk/*, /opt/android-ndk
  Next step: set ANDROID_NDK_HOME to an Android NDK r30 or newer, e.g.
            set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
endef

define ERR_NO_WRAPPER
ERROR: NDK found at $(NDK_TOOLCHAIN) but it has no aarch64-linux-android$(API)-clang wrapper.
  That wrapper is missing on NDK releases older than r30. Next step: install a
  newer Android NDK and set ANDROID_NDK_HOME to it, e.g.
            set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
endef

define ERR_NO_PSL2
ERROR: psl2 needs an NDK providing an aarch64-linux-android$(PSL2_API) wrapper (r29 only goes up to 35).
  Next step: set ANDROID_NDK_HOME to an Android NDK r30 or newer, e.g.
            set ANDROID_NDK_HOME=D:\android-ndk\android-ndk-r30
endef

check-ndk:
	$(if $(NDK_TOOLCHAIN),,$(error $(ERR_NO_NDK)))
	$(if $(CC),,$(error $(ERR_NO_WRAPPER)))

check-psl2-cc:
	$(if $(PSL2_CC),,$(error $(ERR_NO_PSL2)))

hijtest: hijack_test.c | check-ndk
	"$(CC)" $(HOSTED_CFLAGS) $< -o $@

slot_restore: slot_restore.c | check-ndk
	"$(CC)" $(HOSTED_CFLAGS) $< -o $@

psl2: perf_slide.c | check-psl2-cc
	"$(PSL2_CC)" -static -O2 -s $< -o $@

bandscan: bandscan.c | check-psl2-cc
	"$(PSL2_CC)" -static -O2 $< -o $@

clean:
	@$(call RM_F,hijtest)
	@$(call RM_F,slot_restore)
	@$(call RM_F,psl2)
	@$(call RM_F,bandscan)
