# KPM-Spore

[English](./README_EN.md)

KernelPatch 模块的构建脚手架。写完 C 代码，跑一下 `./build.sh`，就能拿到 `.kpm` 文件。NDK 和 KernelPatch 源码都是自动拉的，不用操心。

最早是给 [Zygisk-MyInjector](https://github.com/jiqiu2022/Zygisk-MyInjector) 的内核隐藏功能写的，后来觉得做成通用的比较方便。

> 如果加载 `.kpm` 报符号错误，多半是 KernelPatch 版本没对上。检查一下手机 APatch 的版本和项目里拉取的源码是不是同一个。默认拉 main 分支最新代码。

## 快速开始

```bash
git clone https://github.com/jiqiu2022/kpm-spore.git
cd kpm-spore

# 构建全部
./build.sh

# 只构建一个
cmake --build build --target hello

# 新建模块
./new-module.sh my-module "你的名字" "这个模块做什么"
```

产物在 `build/<模块名>/<模块名>.kpm`。Windows 用 `.bat` 脚本。

## 部署到手机

项目带了个叫 `kpmctl` 的小工具，通过 KernelPatch 的 supercall 接口（syscall 45）跟内核通信，可以直接在 shell 里加载、卸载、查看模块。

一条命令搞定构建到加载：

```bash
# 全部模块：构建 → adb push → 加载
./deploy.sh <superkey>

# 指定模块
./deploy.sh <superkey> hello

# 看看加载了啥
./deploy.sh <superkey> --list

# 卸载
./deploy.sh <superkey> --unload kpm-hello
```

也可以手动来：

```bash
# 编译 kpmctl（静态链接的 aarch64 二进制）
bash tools/kpmctl/build.sh

# 推到手机
adb push tools/kpmctl/kpmctl /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kpmctl

# 用
adb shell /data/local/tmp/kpmctl <superkey> hello
adb shell /data/local/tmp/kpmctl <superkey> load /data/local/tmp/hello.kpm
adb shell /data/local/tmp/kpmctl <superkey> list
adb shell /data/local/tmp/kpmctl <superkey> unload kpm-hello
```

## 目录结构

```
kpm-spore/
├── modules/              # 模块源码，一个目录一个模块
│   ├── hello/
│   ├── hidemap/
│   ├── injectHide/
│   ├── trace_guard/      # ⚠️ [未验证] 注入痕迹隐藏（组合模块）
│   ├── trace_maps/       # ⚠️ [未验证] maps 隐藏（独立）
│   ├── trace_mount/      # ⚠️ [未验证] 挂载点隐藏（独立）
│   ├── trace_syscall/    # ⚠️ [未验证] 系统调用拦截（独立）
│   ├── trace_debug/      # ⚠️ [未验证] 调试信息隐藏（独立）
│   ├── root_guard/       # ⚠️ [未验证] Root 检测绕过（组合模块）
│   ├── root_maps/        # ⚠️ [未验证] VMA maps 隐藏（独立）
│   ├── root_syscall/     # ⚠️ [未验证] syscall 拦截（独立）
│   ├── root_setuid/      # ⚠️ [未验证] zygote/setuid hook（独立）
│   └── template/         # 新模块的骨架
├── shared/               # 共享源码（不直接编译）
│   ├── trace/            # trace_guard 家族共享代码
│   └── root/             # root_guard 家族共享代码
├── tools/kpmctl/         # 命令行加载工具
├── third_party/          # KernelPatch 源码（自动下载）
├── build.sh
├── deploy.sh
├── new-module.sh
└── CMakeLists.txt
```

## 未验证模块说明

> ⚠️ 标记为 `[未验证]` 的模块**尚未在真实设备上测试**。使用前请自行评估风险。
>
> 这些模块包含两个家族：
> - **trace_guard 家族**：隐藏注入痕迹、挂载点、调试信息、SELinux 上下文等。`trace_guard` 是组合模块（包含全部功能），也可以单独加载 `trace_maps`、`trace_mount`、`trace_syscall`、`trace_debug`。
> - **root_guard 家族**：绕过 Root/Magisk 检测，通过 syscall 拦截和 VMA 隐藏实现。`root_guard` 是组合模块，也可以单独加载 `root_maps`、`root_syscall`、`root_setuid`。

## 共享源码与 components.cmake

模块可以通过 `components.cmake` 引用 `shared/` 下的共享源文件：

```cmake
# modules/trace_maps/components.cmake
set(EXTRA_SOURCES
    ${CMAKE_SOURCE_DIR}/shared/trace/symbols.c
    ${CMAKE_SOURCE_DIR}/shared/trace/maps.c
)
set(EXTRA_INCLUDES ${CMAKE_SOURCE_DIR}/shared/trace)
```

构建系统会自动加载 `components.cmake` 并将共享源文件编入模块。

## 写模块

最快的办法：

```bash
./new-module.sh my-module "Name" "说明"
```

生成的 `module.c` 里该填的都标好了。手动建也行，从 `modules/template` 复制一份改。

一个模块长这样：

```c
KPM_NAME("kpm-my-module");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Name");
KPM_DESCRIPTION("做什么用的");

static long my_init(const char *args, const char *event, void *__user reserved) {
    pr_info("loaded\n");
    return 0;
}

static long my_exit(void *__user reserved) {
    pr_info("unloaded\n");
    return 0;
}

KPM_INIT(my_init);
KPM_EXIT(my_exit);
```

需要从用户态控制模块的话加 `KPM_CTL0` / `KPM_CTL1`。接口定义在 KernelPatch 的 `kernel/include/kpmodule.h`。

## 配置

NDK 路径自动检测。找不到就自己指定：

```bash
cp env.example .env
# NDK_PATH=/your/ndk/path
```

## 常见问题

**"No module found"** — `modules/` 下面没有模块（template 不算）。建一个就好。

**NDK 找不到** — 设 `NDK_PATH` 环境变量，指向有 `toolchains/` 目录的那层。

**加载失败** — 先 `kpmctl <key> hello` 确认 KernelPatch 在跑。再看版本对不对。

## 致谢

- [KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere/) — NDK 构建 KPM 的思路来源
- [KernelPatch](https://github.com/bmax121/KernelPatch) — 内核补丁框架

## 许可证

GPL v2 or later
