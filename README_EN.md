# KPM-Spore

[中文](./README.md)

A build scaffold for KernelPatch modules (KPM). Write your C code, run `./build.sh`, get a `.kpm` file. NDK detection and KernelPatch source download are handled automatically.

Originally built for the kernel-level hiding feature in [Zygisk-MyInjector](https://github.com/jiqiu2022/Zygisk-MyInjector), later extracted as a standalone tool.

> If you get symbol errors when loading a `.kpm`, the KernelPatch version on your phone probably doesn't match the source pulled by this project. Check your APatch version. By default we pull the latest main branch.

## Quick start

```bash
git clone https://github.com/jiqiu2022/kpm-spore.git
cd kpm-spore

# Build everything
./build.sh

# Build one module
cmake --build build --target hello

# Create a new module
./new-module.sh my-module "Your Name" "What it does"
```

Output goes to `build/<module>/<module>.kpm`. On Windows, use the `.bat` scripts.

## Deploy to device

The repo includes `kpmctl`, a small static aarch64 binary that talks to KernelPatch via the supercall interface (syscall 45). It can load, unload, list, and control modules from a shell.

One command to build, push, and load:

```bash
# All modules
./deploy.sh <superkey>

# One module
./deploy.sh <superkey> hello

# Check what's loaded
./deploy.sh <superkey> --list

# Unload
./deploy.sh <superkey> --unload kpm-hello
```

Or do it manually:

```bash
# Build kpmctl
bash tools/kpmctl/build.sh

# Push to device
adb push tools/kpmctl/kpmctl /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kpmctl

# Use it
adb shell /data/local/tmp/kpmctl <superkey> hello
adb shell /data/local/tmp/kpmctl <superkey> load /data/local/tmp/hello.kpm
adb shell /data/local/tmp/kpmctl <superkey> list
adb shell /data/local/tmp/kpmctl <superkey> unload kpm-hello
```

## Project layout

```
kpm-spore/
├── modules/              # Module sources, one directory per module
│   ├── hello/
│   ├── hidemap/
│   ├── injectHide/
│   └── template/         # Skeleton for new modules
├── tools/kpmctl/         # CLI loader tool
├── third_party/          # KernelPatch source (auto-downloaded)
├── build.sh
├── deploy.sh
├── new-module.sh
└── CMakeLists.txt
```

## Writing a module

Fastest way:

```bash
./new-module.sh my-module "Name" "Description"
```

This generates a `module.c` with all the blanks marked. You can also copy `modules/template` manually.

A minimal module:

```c
KPM_NAME("kpm-my-module");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Name");
KPM_DESCRIPTION("What this does");

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

For userspace control, add `KPM_CTL0` / `KPM_CTL1`. See `kernel/include/kpmodule.h` in KernelPatch for the full API.

## Configuration

NDK path is auto-detected. If that fails, specify it:

```bash
cp env.example .env
# NDK_PATH=/your/ndk/path
```

## Troubleshooting

**"No module found"** — No valid modules under `modules/` (template is skipped). Create one.

**NDK not found** — Set `NDK_PATH` to the directory containing `toolchains/`.

**Module won't load** — Run `kpmctl <key> hello` first to confirm KernelPatch is active. Then check version compatibility.

## Credits

- [KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere/) — the original idea of building KPM with NDK
- [KernelPatch](https://github.com/bmax121/KernelPatch) — the kernel patching framework

## License

GPL v2 or later
