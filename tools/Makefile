API      ?= 35
PSL2_API ?= 37

NDK_CANDIDATES := $(ANDROID_NDK_HOME) $(ANDROID_NDK_ROOT) \
                  $(wildcard $(HOME)/android-ndk-cache/android-ndk-*) \
                  /opt/android-ndk
NDK_TOOLCHAIN := $(firstword $(foreach n,$(NDK_CANDIDATES),\
                     $(wildcard $(n)/toolchains/llvm/prebuilt/linux-x86_64)))
CC      := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
PSL2_CC := $(firstword $(foreach n,$(NDK_CANDIDATES),\
               $(wildcard $(n)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(PSL2_API)-clang)))

HOSTED_CFLAGS := -static -O2

BINS := hijtest slot_restore psl2 r829_bandscan

.PHONY: all clean check-ndk $(BINS)

all: hijtest slot_restore psl2

check-ndk:
	@test -x "$(CC)" || { echo "ERROR: 未找到Android NDK（需要aarch64-linux-android$(API) wrapper）。" >&2; \
	   echo "       查找顺序: \$$ANDROID_NDK_HOME、\$$ANDROID_NDK_ROOT、" >&2; \
	   echo "                 \$$HOME/android-ndk-cache/android-ndk-*、/opt/android-ndk" >&2; \
	   echo "       设ANDROID_NDK_HOME指向你的NDK目录。" >&2; exit 1; }

hijtest: hijack_test.c | check-ndk
	$(CC) $(HOSTED_CFLAGS) $< -o $@

slot_restore: slot_restore.c | check-ndk
	$(CC) $(HOSTED_CFLAGS) $< -o $@

psl2: perf_slide.c
	@test -n "$(PSL2_CC)" || { echo "ERROR: psl2需要提供API$(PSL2_API) wrapper的NDK(r29只到35)。" >&2; \
	   echo "       设ANDROID_NDK_HOME指向r30或更新。" >&2; exit 1; }
	$(PSL2_CC) -static -O2 -s $< -o $@

r829_bandscan: r829_bandscan.c
	$(PSL2_CC) -static -O2 $< -o $@

clean:
	rm -f $(BINS)
