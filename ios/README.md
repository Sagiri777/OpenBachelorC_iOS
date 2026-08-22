# OpenBachelorC iOS

`ios/` 是 OpenBachelorC 的 macOS 宿主端控制器、Frida Agent 和 direct profile
工具链。宿主程序在 Mac 上运行，通过 USB 或远程 Frida 连接 iPhone；它不是一个可在
iPhone 上独立运行的 Python App。`launcher/` 另提供一个 TrollStore 原生启动器，可连接
目标 App 内的 Frida Gadget，或连接越狱环境的本机 `frida-server`；完成一次性准备后，
每次启动、注入和本机抓包均不需要连接 Mac 或运行宿主控制器。

当前提供三条运行路径：

- 越狱设备：iPhone 运行 `frida-server`，Mac 对目标应用执行 `attach` 或 `spawn`。
- TrollStore + Gadget：向已解密 IPA 注入 Frida Gadget，安装后由同一控制器连接。
- TrollStore 设备端：launcher 在手机本机自动持久注入 Gadget，再唤起并连接目标 App。

工具还可以从已授权设备上的运行进程导出解密后的 `UnityFramework`、其它应用内
Mach-O 和 `global-metadata.dat`，并结合 Il2CppDumper 产物生成新版本 direct profile。

> 仅在你拥有或明确获准测试的设备、应用和账号上使用。设备导出物包含应用代码，
> 网络捕获可能包含账号凭据和完整玩家数据；不要提交到 Git、公开上传或分发。

## 功能概览

| 功能 | 状态 | 说明 |
|---|---|---|
| `doctor` | 可用 | 检查 Frida 设备、目标应用、版本/build、PID、宿主 Frida 和 `ldid` |
| `build` | 可用 | 编译 `probe`、`direct`、`core`、`extra`、`trainer` Agent |
| `run` + direct profile | 当前推荐 | 按 bundle/version/build 选择 profile，支持网络重写/捕获，并通过校验 RVA 尽量启用 extra 与 trainer |
| `profile decrypt --device` | 可用，已实机验证 | 从运行进程导出明文 `UnityFramework`、其它已加载应用 Mach-O 和 metadata |
| `profile decrypt SOURCE` | 可用 | 整理并校验已解密 IPA、`.app`、解包目录、flat dump 或单个 Mach-O |
| `profile generate` | 可用，已实机验证 | 从解密二进制、`script.json` 和 `dump.cs` 生成 fail-closed direct profile |
| `profile generate --auto-decrypt` | 可用，已实机验证 | 在生成 profile 前自动执行设备导出或本地输入整理 |
| `patch-ipa` | 可用 | 向已解密 IPA 注入 Frida Gadget，可选修改 ATS 并用 `ldid` 重签 |
| 设备端 Launcher | 可构建，待实机回归 | 独立 helper + 状态握手；支持纯 TrollStore Gadget 或越狱 Frida，本机抓包落盘/URL 重定向 |
| `probe` | 可用 | 报告 Darwin/arm64、`UnityFramework` 和 IL2CPP export 状态，不安装业务 hook |
| `core` / `extra` / `trainer` | 兼容旧路径 | 独立 Agent 依赖未裁剪 IL2CPP exports；direct profile 已内置 best-effort extra/trainer，不再需要重复加载 |
| Android Java hook | 不适用 | iOS 不存在 `Java.perform`、OkHttp Java 层或 `android_dlopen_ext` |

当前内置 profile 是
[`profiles/arknights-2.7.61-59.json`](profiles/arknights-2.7.61-59.json)，目标为
`com.hypergryph.arknights` 2.7.61 (59)。该构建的 IL2CPP exports 已裁剪，默认运行时
加载 `probe + direct`。内置 profile 还包含 extra 的可校验 RVA：即使 IL2CPP exports 已
裁剪，direct 也能安装 `pause_deploy`、`3x_speed`，并在原生悬浮窗显示战斗时间与 Tick；
仅当必要 IL2CPP export 存在时，`vision` 才会异步尝试使用 IL2CPP bridge。内置 profile
提供 36 个 trainer RVA，当前 direct fallback 可按项控制 18/20 个命令；`global_range`
与 `allow_dup_char` 仍需兼容旧
bridge，`unlimited_token` 与 `true_aoe` 是避开 arm64 结构体 ABI/泛型 post-filter 的降级实现。
状态中的 `capabilities.extra_features`、`capabilities.trainer_commands` 会列出实际可用功能。
可选能力不可用不会阻塞 `direct-ready`、网络捕获或其它 direct hook；`core`、独立 `extra`
和独立 `trainer` 仍只在显式旧路径中加载。

## 环境要求

宿主端：

- macOS；IPA 打包依赖系统自带的 `ditto`。
- Python `>=3.12,<3.15`，由 `uv` 按 `pyproject.toml` 管理。
- `uv`。
- Node.js `>=20,<26`，推荐 Node.js 20 或 22。Node.js 26 不在支持范围内。
- 与设备端完全一致的 Frida 版本；项目锁定为 `17.9.1`。
- Il2CppDumper，仅在为新游戏版本生成 profile 时需要。
- `ldid`，仅在 `patch-ipa` 需要本地重签时使用。
- `iproxy`，仅在 Gadget 需要 USB 端口转发时使用。

设备端二选一：

- 已越狱 arm64 iPhone，并运行匹配版本的 iOS `frida-server`。
- TrollStore 设备，目标 App 包含至少一个可安全修改的未加密 embedded framework/dylib；
  如果没有，则需通过 TrollFools 兼容包或 `patch-ipa` 处理已解密 IPA。

不要将仓库中的 Android `frida-server` 或 Gadget 用到 iOS。rootless 越狱也应安装与
越狱环境匹配的 iOS Frida 软件包。

## 安装与构建

以下命令均假设当前位于仓库根目录：

```bash
cd ios
uv sync --locked --dev
npm ci
uv run --locked openbachelor-ios build
```

也可以使用 Makefile：

```bash
cd ios
make install
make build
```

若仓库中没有 `config.json`，以
[`config.example.json`](config.example.json) 为模板创建一份。默认目标 bundle id 是
`com.hypergryph.arknights`。命令行的 `--config`、`--bundle-id`、`--mode` 和
`--remote` 会覆盖对应配置。

检查 CLI 是否安装成功：

```bash
uv run --locked openbachelor-ios --help
uv run --locked openbachelor-ios profile --help
```

## 目录结构

```text
ios/
|-- openbachelor_ios/       # Python CLI、设备连接、导出、profile 和 IPA 工具
|-- frida/                  # TypeScript Agent 源码
|-- build/                  # 编译后的 Agent JavaScript
|-- profiles/               # 按版本管理的 direct profile
|-- dumps/                  # 本地分析输入；不要提交受版权保护的 dump
|-- captured/               # 可选网络捕获；包含敏感数据
|-- launcher/               # TrollStore/越狱设备端原生启动器与 IPA 构建脚本
|-- tests/                  # Python 测试
|-- config.example.json     # 完整配置示例
|-- pyproject.toml
|-- uv.lock
|-- package.json
`-- Makefile
```

推荐的新版本 dump 结构：

```text
dumps/3.0.0-60/
|-- UnityFramework
|-- global-metadata.dat
|-- decryption-manifest.json
|-- modules/
|   |-- AppExecutable
|   `-- OtherFramework
`-- il2cppdumper/
    |-- script.json
    `-- dump.cs
```

本地 `.ipa` 或 `.app` 输入还会保留 `Payload/<App>.app/`。设备模式只导出已加载的
应用 Mach-O 和 metadata，不会重建完整 `.app` 或 IPA。

## 使用已有 Profile

### 1. 检查设备

USB 连接并信任 iPhone，保持设备解锁，确认设备端 `frida-server` 正在运行：

```bash
cd ios
uv run --locked openbachelor-ios doctor --mode jailbreak
```

`doctor` 的 `target` 应显示：

- `installed: true`
- 正确的 `bundle_id`
- 当前 `version` 和 `build`
- 应用已运行时的非零 `pid`

`host_tools.frida_version` 应与设备端一致。`ldid` 为 `null` 不影响越狱模式或 profile
生成，只影响 Gadget IPA 重签。

### 2. Attach 并运行

先在 iPhone 上手动打开目标应用，再执行：

```bash
uv run --locked openbachelor-ios run --mode jailbreak --attach
```

默认按设备报告的 `bundle_id + version + build` 唯一选择 profile。也可以显式指定
profile id 或 JSON 路径：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --profile arknights-2.7.61-59

uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --profile profiles/arknights-2.7.61-59.json
```

显式指定 profile 不会绕过 bundle/version/build 校验。正常启动应看到
`direct-module`，随后是 `direct-ready`，且 `hook_errors` 为空。

首次检查未知版本时只加载探针：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach --probe-only
```

`--probe-only` 不会安装 direct hooks，也不会验证新 profile 的偏移；它只用于确认平台、
模块和 export 状态。

## 为新版本生成 Profile

游戏更新通常会改变 `UnityFramework` UUID、函数 RVA、prologue 和托管对象布局。不能只
复制旧 profile 并修改版本号。完整流程是：

```text
运行中的已授权应用
        |
        v
导出 UnityFramework + global-metadata.dat
        |
        v
Il2CppDumper -> script.json + dump.cs
        |
        v
profile generate -> profiles/<id>.json
        |
        v
probe + 短会话实机验证
```

### 1. 确认目标身份

```bash
uv run --locked openbachelor-ios doctor \
  --mode jailbreak \
  --bundle-id com.hypergryph.arknights
```

记录 `version` 和 `build`。以下示例用 `3.0.0` 和 `60` 作为占位值，请替换为设备上的
实际结果。

### 2. 从设备导出明文映像

让工具启动一个新进程并在模块加载后导出：

```bash
uv run --locked openbachelor-ios profile decrypt \
  --device --spawn \
  --mode jailbreak \
  --bundle-id com.hypergryph.arknights \
  --output-dir dumps/3.0.0-60 \
  --timeout 300
```

若需要保留当前登录态，先手动启动应用，然后 attach：

```bash
uv run --locked openbachelor-ios profile decrypt \
  --device --attach \
  --mode jailbreak \
  --bundle-id com.hypergryph.arknights \
  --output-dir dumps/3.0.0-60 \
  --timeout 300
```

默认导出 `UnityFramework` 和所有已加载、路径位于目标 `.app` 内的 Mach-O。只需要
`UnityFramework` 时可以限制额外模块：

```bash
uv run --locked openbachelor-ios profile decrypt \
  --device --spawn \
  --output-dir dumps/3.0.0-60 \
  --module UnityFramework
```

`--module` 可重复传入模块名或完整设备路径；无论是否限制，`UnityFramework` 都是必需
输出。无法或无需导出 metadata 时可传 `--no-metadata`，但生成的 profile 会缺少
metadata 身份信息并给出 warning。

导出成功后，CLI 输出 JSON，其中列出：

- `output_dir`
- 根目录的 `UnityFramework`
- 可选的 `global-metadata.dat`
- 所有导出模块
- fallback 或 `cryptid` 处理 warning

`decryption-manifest.json` 记录来源、模块相对路径、SHA-256 和 warning。

### 3. 运行 Il2CppDumper

使用刚导出的同一对文件。以 Il2CppDumper 的 .NET 入口为例：

```bash
dotnet /path/to/Il2CppDumper.dll \
  dumps/3.0.0-60/UnityFramework \
  dumps/3.0.0-60/global-metadata.dat \
  dumps/3.0.0-60/il2cppdumper
```

不同 Il2CppDumper 发行版的启动命令可能不同，但输出目录必须至少包含：

```text
script.json
dump.cs
```

两者必须来自同一版 `UnityFramework` 和 `global-metadata.dat`。工具不会自动下载或运行
Il2CppDumper，也不会根据版本号猜测偏移。

### 4. 生成 Direct Profile

```bash
uv run --locked openbachelor-ios profile generate \
  --dump-dir dumps/3.0.0-60 \
  --bundle-id com.hypergryph.arknights \
  --version 3.0.0 \
  --build 60 \
  --unity-version 2021.3.39f1
```

生成器会自动查找 `UnityFramework`、`global-metadata.dat`、
`il2cppdumper/script.json` 和 `il2cppdumper/dump.cs`。默认输出为：

```text
profiles/arknights-3.0.0-60.json
```

也可以显式指定所有输入和输出：

```bash
uv run --locked openbachelor-ios profile generate \
  --module dumps/3.0.0-60/UnityFramework \
  --metadata dumps/3.0.0-60/global-metadata.dat \
  --script-json dumps/3.0.0-60/il2cppdumper/script.json \
  --dump-cs dumps/3.0.0-60/il2cppdumper/dump.cs \
  --bundle-id com.hypergryph.arknights \
  --version 3.0.0 \
  --build 60 \
  --id arknights-3.0.0-60 \
  --unity-version 2021.3.39f1 \
  --output profiles/arknights-3.0.0-60.json
```

若 `UnityFramework` 仍处在被整理后的 `Payload/<App>.app` 内，生成器会优先从该 App 的
`Info.plist` 读取 bundle id、version、build 和可用的 Unity 版本。flat dump 或单文件
输入没有 App `Info.plist`，必须显式提供缺失的身份字段。

### 5. 实机验证新 Profile

先运行只读探针：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach --probe-only
```

再用新 profile 做一次短会话：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --profile arknights-3.0.0-60
```

只有同时满足以下条件才应继续使用：

- 出现 `direct-ready`。
- `module_uuid` 与 profile 一致。
- `hook_errors` 为 `[]`。
- 没有 `direct-profile-mismatch`、`direct-error` 或 prologue mismatch。
- 应用基础登录和请求流程仍正常。

### 自动导出后直接生成

`--auto-decrypt` 会在 profile 生成前调用设备导出器。它不能替代 Il2CppDumper，所以这条
命令适用于已经有同版本 `script.json` 和 `dump.cs` 的场景：

```bash
uv run --locked openbachelor-ios profile generate \
  --auto-decrypt --device --spawn \
  --mode jailbreak \
  --bundle-id com.hypergryph.arknights \
  --decrypt-output dumps/3.0.0-60-fresh \
  --script-json il2cpp-artifacts/3.0.0-60/script.json \
  --dump-cs il2cpp-artifacts/3.0.0-60/dump.cs \
  --unity-version 2021.3.39f1 \
  --output profiles/arknights-3.0.0-60.json \
  --timeout 300
```

设备模式会尝试自动读取已安装应用的 bundle id、version 和 build；显式参数优先。建议
始终显式设置 `--decrypt-output`，避免把大型导出写入默认的 `dumps/device-export`。

如果 Il2CppDumper 产物已在同一个 dump 目录中，可原地刷新：

```bash
uv run --locked openbachelor-ios profile generate \
  --auto-decrypt --device --spawn \
  --decrypt-output dumps/3.0.0-60 \
  --script-json dumps/3.0.0-60/il2cppdumper/script.json \
  --dump-cs dumps/3.0.0-60/il2cppdumper/dump.cs \
  --unity-version 2021.3.39f1 \
  --output profiles/arknights-3.0.0-60.json \
  --timeout 300 \
  --force
```

此处 `--force` 同时允许刷新 dump 和覆盖 profile。导出器会保留
`il2cppdumper/`、笔记等非导出工件，但会替换旧的 `Payload`、`modules`、`resources`、
`UnityFramework`、metadata 和 manifest。执行前确认输出路径正确。

## 本地输入整理

`profile decrypt SOURCE` 的本地模式不会连接设备。它接受以下输入：

| 输入 | 行为 |
|---|---|
| 已解密 `.ipa` 或 `.zip` | 安全解包，要求 `Payload` 中恰好一个 `.app`，递归校验 Mach-O |
| `.app` 目录 | 复制到 `Payload/<App>.app`，校验所有 Mach-O |
| 已解包且包含 `Payload/` 的目录 | 保留目录结构并校验 |
| flat dump 目录 | 要求根目录存在 `UnityFramework`，可同时包含 metadata 和 Il2CppDumper 产物 |
| 单个 `UnityFramework` 或其它 Mach-O | 整理为根目录 `UnityFramework`；metadata 需单独提供 |

### 已解密 IPA

```bash
uv run --locked openbachelor-ios profile decrypt \
  MyDecrypted.ipa \
  --output-dir dumps/3.0.0-60
```

### `.app` 或 flat dump

```bash
uv run --locked openbachelor-ios profile decrypt \
  MyGame.app \
  --output-dir dumps/3.0.0-60

uv run --locked openbachelor-ios profile decrypt \
  ThirdPartyFlatDump \
  --output-dir dumps/3.0.0-60
```

### 单独的 UnityFramework

```bash
uv run --locked openbachelor-ios profile decrypt \
  ThirdPartyDump/UnityFramework \
  --output-dir dumps/3.0.0-60
```

随后生成 profile 时显式传入 metadata：

```bash
uv run --locked openbachelor-ios profile generate \
  --dump-dir dumps/3.0.0-60 \
  --metadata ThirdPartyDump/global-metadata.dat \
  --script-json ThirdPartyDump/il2cppdumper/script.json \
  --dump-cs ThirdPartyDump/il2cppdumper/dump.cs \
  --bundle-id com.hypergryph.arknights \
  --version 3.0.0 \
  --build 60
```

`profile generate --source PATH` 会隐式启用本地准备阶段，`--auto-decrypt` 是更明确的同义
写法。例如：

```bash
uv run --locked openbachelor-ios profile generate \
  --source MyDecrypted.ipa \
  --decrypt-output dumps/3.0.0-60 \
  --script-json il2cpp-artifacts/3.0.0-60/script.json \
  --dump-cs il2cpp-artifacts/3.0.0-60/dump.cs
```

命名形式 `--source`、`--ipa` 和 `--app` 是同一个参数的别名。

### `--assume-memory-dump`

第三方工具有时已经导出了明文内存页，却留下非零 `cryptid`。只有在你独立确认加密区
内容确实是明文时，才可以：

```bash
uv run --locked openbachelor-ios profile decrypt \
  ThirdPartyDump/UnityFramework \
  --output-dir dumps/3.0.0-60 \
  --assume-memory-dump
```

该选项只清除 Mach-O 的加密标记，不会把 FairPlay 密文变成明文。对原始 App Store IPA
使用它会得到损坏、不可分析的结果，因此本地模式默认拒绝任何仍标记为加密的 Mach-O。

## 设备导出与 FairPlay 边界

设备导出器的工作方式是：

1. 枚举目标 `.app` 内已加载的模块。
2. 优先读取设备文件系统中的原始 Mach-O，保留完整 file-backed 布局。
3. 解析 thin 或 FAT Mach-O，定位当前运行架构和 `LC_ENCRYPTION_INFO`。
4. 仅用运行进程中的明文页覆盖 FairPlay 加密区，并清除对应 `cryptid`。
5. 设备文件不可读且尚未开始输出时，回退为分析用内存镜像并记录 warning。
6. 分块校验顺序和长度，验证所有 stream 已完整结束，再原子安装输出目录。
7. 校验 metadata 非空、magic `0xFAB11BAF` 和正数 version。

以下边界不能混淆：

- 修改 `cryptid` 本身不是解密。
- 原始加密 IPA 无法只在 Mac 上离线恢复明文。
- 设备导出物用于逆向分析、Il2CppDumper 和 profile 校验，不是可直接重签安装的 IPA。
- 设备模式只导出运行时已加载的应用模块，不包含完整资源和签名结构。
- Gadget 注入仍要求一份完整且已解密的 IPA；进程导出目录不能直接作为其输入。

输出采用暂存目录和原子替换。缺块、乱序、重复 stream、长度不符、session 中断或 metadata
损坏都会使整个操作失败，不留下伪装成成功的半截导出。

## Profile 严格校验

生成器采取 fail-closed 策略：

- 要求 `UnityFramework` 是可解析的 arm64/arm64e Mach-O，且没有未处理的 FairPlay 加密。
- 流式读取大型 `script.json`，按 Il2CppDumper 方法名和完整签名解析 32 个必需 hook。
- 重载必须唯一，所有 RVA 必须落在可执行 `__text` 内。
- 保存 Mach-O UUID、SHA-256、文本段范围和每个函数的 8 字节 prologue。
- 从 `dump.cs` 解析 UnityWebRequest、BestHTTP 和响应对象所需字段布局。
- 校验并记录 metadata version 和 SHA-256。
- 输出已存在时拒绝覆盖，只有明确传入 `--force` 才替换。

`dump.cs` 缺少任一必需布局时默认失败。只有人工确认新旧构建的托管对象布局相同，才可
显式继承参考 profile：

```bash
uv run --locked openbachelor-ios profile generate \
  --dump-dir dumps/3.0.0-60 \
  --bundle-id com.hypergryph.arknights \
  --version 3.0.0 \
  --build 60 \
  --allow-layout-fallback \
  --reference-profile profiles/arknights-2.7.61-59.json
```

运行时还有第二层校验：

- 自动选择要求 bundle/version/build 唯一匹配。
- 显式 profile 仍检查已知的 bundle/version/build。
- direct Agent 在安装 hook 前比较运行中 `UnityFramework` UUID。
- 每个地址必须属于可执行内存，且当前 prologue 必须与 profile 一致。
- 任一条件不满足会报告 mismatch/error，而不是继续安装错误偏移。

metadata 哈希用于生成物溯源；当前运行时守卫以应用身份、模块 UUID、可执行地址和
prologue 为准。

## Attach 与 Spawn

| 模式 | 适用场景 | 注意事项 |
|---|---|---|
| `--attach` | 应用已手动启动；希望保留登录态或避开系统 launch 限制 | 必须连接到当前有效 PID，且应用不能在连接过程中重启 |
| `--spawn` | 希望从全新进程开始，在启动早期加载导出器或 Agent | iPhone 必须保持解锁；spawn 权限和 Frida server entitlement 必须正常 |

两种方式均已在当前实机环境验证。若遇到旧后台进程、stale PID 或 dyld 探测错误：

1. 从多任务界面彻底退出目标应用。
2. 再次运行 `doctor`，确认 PID 已清零或变为新 PID。
3. 使用 `--spawn` 创建干净进程；或手动重新打开应用后立即 `--attach`。
4. 不要复用已经 detached 的 Frida session。

若 spawn 报告设备未解锁，保持屏幕解锁后重试，或改为手动启动加 `--attach`。

## 越狱模式

1. 在 iPhone 上安装并启动 iOS Frida `17.9.1`。宿主和设备小版本也应一致。
2. USB 连接、解锁并信任设备。
3. 运行 `doctor --mode jailbreak`。
4. 手动启动应用后 `run --attach`，或使用 `run --spawn`。

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --spawn
```

只有确认目标是未裁剪且兼容旧 bridge 的构建时，才使用 legacy Agent：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --legacy-agents
```

推荐直接在 profile 模式启用 trainer。目标恢复后会进入交互式命令行；输入
`enable zero_cost`、`disable zero_cost` 或 `enable all`：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --trainer
```

也可以在 `trainer.startup_commands` 中预设 `enable:<name>`。profile/prologue 校验失败的
命令会报告 `trainer-command-unavailable`，不会退化为未校验地址。只有确认目标未裁剪且与
IL2CPP bridge 兼容、并且确实需要 direct fallback 未覆盖的命令时，才使用旧路径：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --legacy-agents --trainer
```

当前内置 2.7.61 (59) profile 的 direct 命令如下：

- 参考 [ChaomengOrion/Arknights-Assist](https://github.com/ChaomengOrion/Arknights-Assist)
  的功能思路、针对当前 iOS dump 独立实现的 direct 能力：`unlock_fps`（默认目标 120）、
  `battle_speed_16x`（高风险、默认关闭）、`tas_pause` 和动作命令 `tas_step`；悬浮窗可在
  暂停时分别按 Tick 或渲染帧推进，数量支持输入 `1`–`10000`。步进结束后仍保持暂停，
  再关闭 `tas_pause` 即可恢复；
- 完整标量 hook：`zero_cost`、`zero_deploy_cnt`、`deploy_everywhere`、
  `zero_cooldown`、`no_sp`、`withdraw_everything`、`heal_everyone`、
  `unlimited_ammo`、`eat_enemy`、`anti_air`、`no_ban_card`、`cloner_assist`；
- 降级可用：`unlimited_token`（不替换 `ObscuredInt get_maxDeployCnt` 返回结构体）、
  `true_aoe`（提高目标上限，但不跳过两个泛型 post-filter）；
- direct 不可用：`global_range`、`allow_dup_char`。这两项需要兼容的 legacy bridge。

## TrollStore + Gadget

前置条件：

- 从你自己的设备取得的完整已解密 IPA。原始加密 App Store IPA 会被拒绝。
- Frida 官方 iOS universal Gadget，例如
  `frida-gadget-17.9.1-ios-universal.dylib.xz`。
- Mac 上的 `ldid`，除非明确使用外部签名流程。

注入并签名：

```bash
uv run --locked openbachelor-ios patch-ipa \
  MyDecrypted.ipa \
  OpenBachelor-iOS.ipa \
  --gadget vendor/frida-gadget-17.9.1-ios-universal.dylib.xz
```

工具会：

- 要求 IPA 的 `Payload` 中恰好一个 `.app`。
- 验证主可执行文件为未加密 Mach-O。
- 将 Gadget 写入 `Frameworks/FridaGadget.dylib`。
- 添加 `@executable_path/Frameworks/FridaGadget.dylib` 加载命令。
- 生成监听 `127.0.0.1:27042` 且 `on_load: wait` 的 `FridaGadget.config`。
- 尝试保留主程序 entitlements，并用 `ldid` 重签主程序和 Gadget。
- 始终创建新 IPA，不覆盖输入文件，也不覆盖已存在的输出文件。

可选参数：

- `--port 27042`：修改 Gadget 监听端口。
- `--allow-http`：设置 `NSAllowsArbitraryLoads`；仅在确需把 HTTPS 重写到 HTTP 服务时使用。
- `--no-sign`：跳过 `ldid`，供后续外部签名流程使用。

用 TrollStore 安装新 IPA 后打开应用。由于 Gadget 配置为 `on_load: wait`，控制器连接前
应用停在启动阶段是预期行为。可以直接使用设备端 launcher：后端选择
`TrollStore Gadget`，它会在手机本机唤起目标、连接专用的 `127.0.0.1:27043`、加载 direct agent
并恢复进程，不需要以下 Mac 控制器命令。

若仍需从 Mac 调试：

```bash
uv run --locked openbachelor-ios run \
  --mode gadget --attach
```

若 Frida USB provider 无法直接发现 Gadget，可先在另一个终端转发端口：

```bash
iproxy 27042 27042
```

然后连接远程 endpoint：

```bash
uv run --locked openbachelor-ios run \
  --mode gadget --attach \
  --remote 127.0.0.1:27042
```

## TrollStore 设备端启动器（纯 TrollStore / 越狱双后端）

设备端 launcher 把 Frida Core、direct agent 和 profile 打进 TrollStore IPA，在手机上
完成目标唤起、attach、脚本加载和会话保持：

```bash
cd ios
OPENBACHELOR_DOWNLOAD_PROXY=http://127.0.0.1:20122 launcher/build.sh
```

若官方 Frida devkit 已解压，可完全离线重建：

```bash
FRIDA_DEVKIT_DIR=/path/to/frida-core-devkit-17.9.1-ios-arm64 \
FRIDA_GADGET_ARCHIVE=/path/to/frida-gadget-17.9.1-ios-universal.dylib.xz \
TROLLFOOLS_SOURCE_DIR=/path/to/TrollFools \
  launcher/build.sh
```

产物包括：

- `launcher/dist/OpenBachelorLauncher.tipa`：推荐用 TrollStore 直接安装；
- `launcher/dist/OpenBachelorLauncher.ipa`：与 TIPA 内容相同；
- `launcher/dist/OpenBachelorGadget-TrollFools.zip`：可导入 TrollFools 的 Gadget framework，
  作为自动注入不可用时的兼容入口。

在 launcher 中选择后端：

- `TrollStore Gadget`：无需越狱、`frida-server` 或单独安装 TrollFools。Launcher 会先
  备份未加密候选 Mach-O，自动复制、签名并插入内置 Gadget。Gadget 使用专用端口
  `127.0.0.1:27043`，不会与仍在监听 `27042` 的越狱 `frida-server` 冲突；
- `越狱 Frida`：设备本机运行 `frida-server 17.9.1`，launcher 可 spawn/attach 原始目标。

两个后端均可选择：

- 本机抓包：不改写 URL，捕获写入
  “文件”App 的“在我的 iPhone/OB Launcher/Logs/captured/capture.jsonl”和 `bodies/`；
- 服务重定向：将目标请求改写到界面中填写的 HTTP(S) 服务。

启动器使用独立、单实例 helper 保持 Frida session；helper 与界面通过带会话 ID 的
`status.json` 握手。Launcher 内置 Gadget 使用 `on_load: resume`，目标 App 先正常运行，
helper 再附加并加载脚本；系统拒绝自动切换 App 时，也可在一分钟内从桌面手动打开而不会因
等待连接触发启动 watchdog。越狱后端优先附加已运行进程，否则由 `frida-server` 执行
suspended spawn；spawn 失败时回退到系统唤起，并重新枚举真实 PID 后 attach。
之后不依赖 launcher 继续在前台，也不需要 Mac/USB/`iproxy`。
direct agent 默认还会在游戏内安装可拖动、可折叠的原生悬浮控制台，用于查看实时事件摘要、
战斗时间/Tick、切换本会话抓包、逐项控制 Trainer、复制或清空面板内容。可在 Launcher
配置中单独关闭滚动日志而保留紧凑控制面板，收起后关卡内浮标会显示当前 Tick。Trainer 使用
可连续操作的分类网格，并提供可输入数量的 Tick/帧暂停步进；清空面板或隐藏滚动日志都不会
删除磁盘日志。
Launcher 状态卡提供“打开日志位置”，可直接进入系统“文件”界面；也可手动访问
“在我的 iPhone/OB Launcher/Logs”。其中 `session.log` 是当前文本日志，历史文本日志保存为
`session-*.log`，逐会话结构化事件保存为 `events-*.jsonl`，本机抓包位于 `captured/`。
IPA 默认内置当前仓库的 `arknights-2.7.61-59` profile，也可在构建时用
`OPENBACHELOR_PROFILE=/path/to/profile.json` 替换。profile 不匹配时 direct agent 会
fail closed，并在状态卡中显示错误。完整说明见 [`launcher/README.md`](launcher/README.md)。

纯 TrollStore 后端不要求越狱。其精简 injector 复用并注明了 TrollFools MIT 注入流程与
固定提交的设备端工具，只修改 `cryptid == 0` 的 framework/dylib，失败时恢复原始备份；
目标 App 更新后再次点击即可重新注入。没有安全候选时会拒绝修改，可改用 TrollFools ZIP 或
已解密 IPA。Dopamine/KFD 未被捆绑或运行。详细步骤见
[`launcher/README.md`](launcher/README.md)。

## 配置、代理与网络捕获

完整字段见 [`config.example.json`](config.example.json)。direct profile 模式最常用的
配置如下，将该片段合并到 `config.json`：

```json
{
  "bundle_id": "com.hypergryph.arknights",
  "connection": {
    "mode": "jailbreak",
    "transport": "usb",
    "remote_address": "127.0.0.1:27042",
    "timeout_seconds": 20
  },
  "launch": {
    "spawn": false
  },
  "direct": {
    "no_proxy": true,
    "proxy_url": "",
    "capture": false,
    "capture_har": true,
    "capture_output_dir": "captured",
    "capture_max_body_bytes": 4194304,
    "capture_upstream_proxy": "",
    "capture_bridge_host": "",
    "bypass_ssl": true,
    "bypass_signatures": true,
    "block_battle_finish_upload": false,
    "floating_gui": true,
    "floating_log_console": true
  }
}
```

Mac 命令行的 direct profile 模式默认启用游戏内悬浮窗，包括滚动日志和本会话控制；旧的
`config.json` 即使没有这两个字段，也会采用上述默认值。需要关闭时显式设置
`direct.floating_gui=false`；只想隐藏滚动日志并保留紧凑控制面板时设置
`direct.floating_log_console=false`。

使用 direct profile 时，runner 总会加载 `direct`，并按 `scripts.probe` 决定是否同时加载
`probe`。`extra` 配置会传给 direct 内置安装器（默认值无需重复传递）；`--no-extra` 会
关闭 direct RVA 和 bridge 两条 extra 路径。新 profile 会从 `script.json` 尽量生成
`pause_deploy` / `3x_speed` / `battle_timeline`、战斗记录拦截和 direct trainer 所需的可校验 RVA；
缺失这些可选方法不会
阻止网络 profile 生成。`scripts.trainer=true` 或 `--trainer` 会把 trainer 配置传给
direct，并使用同一 direct script 的交互命令通道；`scripts.core` 和独立 trainer Agent
只在显式 `--legacy-agents` 模式加载。

### URL 重写

iPhone 中的 `127.0.0.1` 指向 iPhone 自身，不是 Mac。若 OpenBachelor Server 运行在 Mac
的 `192.168.1.20:8443`：

```json
{
  "direct": {
    "no_proxy": false,
    "proxy_url": "http://192.168.1.20:8443"
  }
}
```

同时确认：

- iPhone 和 Mac 位于可互访的网络。
- macOS 防火墙放行服务端口。
- 服务监听局域网地址，而不只是 Mac 的 `127.0.0.1`。
- 若目标是明文 HTTP，Gadget IPA 已按需要使用 `--allow-http`，或应用已有合适 ATS 配置。

`bypass_ssl` 和 `bypass_signatures` 会修改目标应用的校验结果，仅应用于获授权的测试环境。

### 不上传战斗记录

将 `direct.block_battle_finish_upload` 设为 `true` 后，direct agent 会在游戏的通用
`Networker._PostImpl` 协程选择 BestHTTP、UnityWebRequest 或大请求通道之前检查 URL。末级路径名
包含 `battleFinish`（不区分大小写，包括 `multiBattleFinish`、`singleBattleFinish` 等）或
`saveBattleReplay` 的请求会直接完成，不会创建或发送实际网络请求，并向游戏返回 HTTP 200
和以下本地 JSON：

```json
{
  "result": 0,
  "apFailReturn": 0,
  "expScale": 1.2,
  "goldScale": 1.2,
  "rewards": [],
  "firstRewards": [],
  "unlockStages": [],
  "unusualRewards": [],
  "additionalRewards": [],
  "furnitureRewards": [],
  "alert": [],
  "suggestFriend": false,
  "pryResult": [],
  "playerDataDelta": {"modified": {}, "deleted": {}}
}
```

每次命中都会产生 `battle-finish-blocked` 事件；开启抓包时也不会出现对应的上游 request 事件。
该功能默认关闭。设备端 Launcher 可通过“不上传战斗记录”开关启用。由于服务器不会收到结算，
相关奖励、进度和理智变化不会由服务器持久化。

### 启用捕获

捕获默认关闭。需要记录请求和响应时：

```json
{
  "direct": {
    "capture": true,
    "capture_har": true,
    "capture_output_dir": "captured",
    "capture_max_body_bytes": 4194304
  }
}
```

相对 `capture_output_dir` 以 `ios/` 为基准。输出为：

```text
captured/
|-- capture.jsonl
|-- capture.har
`-- bodies/
    `-- <sha256>.bin
```

- JSONL 记录 URL、headers、状态、body 大小、transport、source 和 sidecar 哈希；自有协议帧没有 URL。
- 捕获会在 session 关闭时自动生成 HAR 1.2。标准 HTTP 请求/响应按 `request_id` 合并；HAR
  可直接导入 Reqable、Fiddler 或其它 HAR 查看器。
- `TorappuSocketNetwork` 自有协议不能原生表达为 HTTP，HAR 会为每个帧生成
  `https://torappu.invalid/socket/...` 合成 URL，并在 `_openbachelor` 扩展中保留协议、方向、主/子 ID、帧头和帧大小。
- BestHTTP 流式分片会聚合到响应内容；原始分片索引、stream ID 和大小保存在
  `_openbachelor_stream_fragments` 扩展中。若最终响应已捕获，HAR 使用最终响应 body，避免重复拼接。
- 可读 UTF-8 body 直接写入 HAR `text`；二进制 body 使用 `encoding: "base64"`，缺失 sidecar
  时保留大小但不伪造内容。
- body 以 SHA-256 命名，超过 `capture_max_body_bytes` 时会标记截断。
- `TorappuSocketNetwork` 的 sidecar 是包含帧头的完整明文帧，并记录主/子协议 ID、方向和帧头大小。
- BestHTTP 流式响应以 `phase=stream` 逐分片记录，`fragment_index` 从 `0` 开始；完成态响应仍会单独记录。
- 终端摘要会移除 URL 用户信息、query、fragment、headers 和 body 内容。
- 捕获目录权限收紧为 `0700`，JSONL 和 body 文件为 `0600`。
- HAR 文件权限为 `0600`；如只需 JSONL/sidecar，可设置 `direct.capture_har` 为 `false`。
- 磁盘文件仍包含原始敏感 headers 和 body；完成分析后应按数据保留策略清理。

记录中的 `transport` 可区分 `UnityWebRequest`、`BestHTTP` 与
`TorappuSocketNetwork`。BestHTTP 记录还包含 `source`，用于判断请求在何处建立、响应在
何处整理，或流式分片在何处进入消费队列。

### 在 Requable / Fiddler 中实时查看

先启动 Requable、Fiddler 或其它支持标准 HTTP 代理的工具，确认它在本机
`127.0.0.1` 的某个端口监听。假设端口是 `8888`：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --capture-proxy-port 8888
```

该参数会自动启用 direct capture、启动一个仅在本次 session 存活的桥接服务，并将
实际游戏请求依次送入查看工具后再访问目标服务器。它不是事后重放，因此写请求不会被
重复发送。终端会显示实际链路，例如：

```text
capture proxy active: iPhone -> 192.168.1.20:43123 -> 127.0.0.1:8888
```

桥接会向查看工具发送原始 absolute URL，因此列表中直接显示
`https://ak-gs-gf.hypergryph.com/account/syncData`，可按原域名或路径搜索。

UnityWebRequest 会在请求构造入口改写 URL；BestHTTP 则会在实际 `System.Uri` 构造时改写
外部目标，并排除 `localhost`、loopback 和本次桥接自身的 origin。终端出现
`"source":"System.Uri.ctor"` 才表示 BestHTTP 真正进入桥接，而不只是捕获记录中的 URL
发生了变化。

桥接入口使用随机端口和会话令牌，退出 `run` 后自动关闭；JSONL 与 body sidecar 仍按
`capture_output_dir` 写入。若自动选择的 Mac 地址不能从 iPhone 访问，可显式指定：

```bash
uv run --locked openbachelor-ios run \
  --mode jailbreak --attach \
  --capture-proxy-port 8888 \
  --capture-host 192.168.1.20
```

需要长期保存在配置中时，可使用等价字段：

```json
{
  "direct": {
    "capture_upstream_proxy": "http://127.0.0.1:8888",
    "capture_bridge_host": "192.168.1.20"
  }
}
```

使用时注意：

- 必须先启动查看工具；端口未监听时 `run` 会在启动目标流量前报错。
- iPhone 必须能访问终端显示的 Mac 地址和随机桥接端口，macOS 防火墙也需放行。
- 桥接会把 HTTP 和 HTTPS 请求以原始 absolute URL 提交给查看工具，再由查看工具连接
  目标服务器。请求不会被隐藏在 `CONNECT` 隧道中，Reqable 列表也不会出现本机桥接
  URL；iPhone 不需要额外安装查看工具的 CA 证书。
- iPhone 到桥接入口是明文 HTTP URL 重写；Gadget 包若受 ATS 限制，需使用
  `patch-ipa --allow-http`，或为测试包配置等价的 ATS 例外。
- `--capture-proxy-port` 仅支持 direct profile 模式，不能与 `--probe-only` 或
  `--legacy-agents` 一起使用。

### 登录后的 `syncData`

`Networker._PostImpl` 会根据请求大小和网络配置选择传输路径。`/account/syncData` 往往
包含完整玩家数据并走 BestHTTP；只观察 UnityWebRequest 可能只能看到启动配置请求。

复测时保持 Frida session 连接，完成一次登录，再检查：

```bash
rg 'account/syncData|"transport":"BestHTTP"' captured/capture.jsonl
```

若终端只有 `event=network-path`，没有对应 `phase=request`/`phase=response`，说明业务路径
已触发，但在请求对象建立或响应整理前失败。若没有 `network-path`，则本次连接未观察到
该登录流程，或捕获并未启用。

## 常见问题

| 现象或错误 | 原因与处理 |
|---|---|
| `Frida server is not reachable` | 确认 USB 信任、设备解锁、iOS `frida-server` 正在运行，且宿主和设备均为 17.9.1 |
| `iPhone is locked` / FBS launch 失败 | 保持设备解锁后重试 `--spawn`，或手动启动应用并改用 `--attach` |
| `<bundle_id> is not running` | attach 模式没有发现运行进程；启动应用，核对 bundle id，再运行 `doctor` |
| stale PID、dyld 探测错误或刚 attach 就 detached | 彻底退出旧进程，运行 `doctor` 核对 PID，再用干净的 spawn 或重新启动后 attach |
| `UnityFramework did not load before export timeout` | 目标进程未进入 Unity 加载阶段、进程重启或模块名不匹配；重新启动并保持前台，再导出 |
| `output directory is not empty` | 使用新的输出目录；确认要替换导出工件时才使用 `--force` |
| `FairPlay-encrypted; use the device exporter` | 本地输入仍是密文；从运行中的已授权应用导出，不要对原始 IPA 使用 `--assume-memory-dump` |
| `global-metadata.dat was not found` | 检查游戏资源布局；可显式提供 `--metadata`，或接受缺少 metadata 身份的 warning |
| `script.json is required` | 用同版本二进制和 metadata 运行 Il2CppDumper，再传 `--script-json` 或正确的 `--dump-dir` |
| `dump.cs did not provide all required managed layouts` | 检查 dump 是否同版本且完整；只有人工验证布局一致后才用 `--allow-layout-fallback` |
| `profile already exists` | 使用新的 `--output`；确认覆盖时传 `--force` |
| `no direct profile matches` | 为当前 version/build 生成 profile，或仅用 `--probe-only` 检查；不要盲用旧 profile |
| `direct-profile-mismatch` | 运行中模块 UUID 与 profile 不同；立即停止使用该 profile 并重新生成 |
| `prologue mismatch` 或 `hook_errors` 非空 | 二进制、Il2CppDumper 产物或 profile 不一致；停止 hook，重新核对全部输入 |
| `patch-ipa` 产物启动后停住 | `patch-ipa` 的 `on_load: wait` 是预期行为；从 Mac 使用 `--mode gadget --attach`，或改用内置 `on_load: resume` 的设备端 launcher 注入 |
| `ldid is required` | 安装 `ldid`，或仅在已有外部签名流程时传 `--no-sign` |
| npm 尝试不兼容构建或安装失败 | 使用 Node.js 20/22，删除错误 Node 环境生成的依赖后重新执行 `npm ci` |

应用退出或 Frida 连接断开时，runner 会打印 `session detached` 并退出。导出阶段发生 detach
会被视为失败，暂存文件会被清理。

## CLI 速查

| 命令 | 用途 |
|---|---|
| `openbachelor-ios build [SCRIPT ...]` | 编译全部或指定 Agent |
| `openbachelor-ios doctor [连接参数]` | 检查设备和目标应用 |
| `openbachelor-ios run [运行参数]` | 选择 profile、attach/spawn 并加载 Agent |
| `openbachelor-ios profile decrypt SOURCE --output-dir DIR` | 整理本地已解密输入 |
| `openbachelor-ios profile decrypt --device --output-dir DIR` | 从运行设备导出明文映像 |
| `openbachelor-ios profile generate --dump-dir DIR` | 从现有 dump 生成 profile |
| `openbachelor-ios profile generate --auto-decrypt ...` | 准备输入后生成 profile |
| `openbachelor-ios patch-ipa INPUT OUTPUT --gadget FILE` | 注入 Frida Gadget |

查看某个子命令的全部参数：

```bash
uv run --locked openbachelor-ios profile decrypt --help
uv run --locked openbachelor-ios profile generate --help
uv run --locked openbachelor-ios run --help
uv run --locked openbachelor-ios patch-ipa --help
```

## 已验证环境

2026-08-20 完成过一次真实设备端到端验证：

| 项目 | 结果 |
|---|---|
| 设备 | iPhone 11，iOS 16.2 |
| Frida | 宿主与设备均为 17.9.1 |
| 目标 | `com.hypergryph.arknights` 2.7.61 (59) |
| 连接方式 | `--spawn` 完成自动导出和 profile 生成；新进程 `--attach` 也验证成功 |
| 导出模块 | `UnityFramework`、`Arknights`、`OpenSSL`、`SSZipArchive`、`hpatchz_dynamic`、`tersafe2` |
| Mach-O 状态 | 6 个模块均可解析且 `encrypted=False`，无导出 warning |
| UnityFramework | UUID `AE59EB96-04B9-3FA5-BB0F-51353713ABA3`，SHA-256 `91e5b85a3b5abf77e451ef0a2b9c1cd2e6d5987f922332f06b1b4f0d47a760e7` |
| Metadata | 43,432,180 字节，version 29，SHA-256 `041d4a22847d0a467b45d408ef66324cbe98423190837558ede82fea9c438376` |
| Profile | 自动识别 bundle/version/build，生成 `32/32` hooks |
| 自动化检查 | `68 passed`，Ruff、TypeScript typecheck 和 Frida 导出 Agent 语法检查通过 |

这组结果证明上述版本和环境的路径可重复工作，不代表新游戏版本可以复用旧偏移。每次更新
仍需重新导出、运行 Il2CppDumper、生成 profile 并做短会话验证。

## 开发与验证

修改 Python 或 Agent 后运行：

```bash
cd ios
UV_CACHE_DIR=.uv-cache uv run --locked python -m pytest -q
UV_CACHE_DIR=.uv-cache uv run --locked ruff check openbachelor_ios tests
npm run typecheck
UV_CACHE_DIR=.uv-cache uv run --locked openbachelor-ios build
```

也可分别使用：

```bash
make test
make lint
make typecheck
make build
```

提交前不要加入以下本地工件：

- 已解密 IPA、`.app`、`UnityFramework` 或其它专有二进制。
- `global-metadata.dat`、Il2CppDumper 大型输出和设备导出目录。
- `captured/` 中的 JSONL、headers、账号数据和 body sidecar。
- 设备标识、配对资料、证书、entitlements 或签名密钥。
