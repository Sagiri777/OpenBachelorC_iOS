# OpenBachelor Launcher (iOS)

这是一个面向 TrollStore/越狱设备的设备端启动器。它加载仓库现有的 direct agent 和版本
profile，启动、注入、抓包和会话保持都在手机上完成，不需要连接 Mac 或运行 Python
控制器。

启动器包含两个后端：

- `TrollStore Gadget`（默认）：无需越狱或 `frida-server`。launcher 会检查目标 App，选择
  可安全修改的未加密 Mach-O，自动安装、签名并持久加载监听 `127.0.0.1:27043` 的
  Frida Gadget 17.9.1；独立端口不会与仍在运行的 `frida-server` 冲突。
- `越狱 Frida`：连接设备本机监听 `127.0.0.1:27042` 的 `frida-server 17.9.1`，支持
  spawn 或 attach 原始目标 App。

共同要求是 iOS 15 或更高版本的 arm64/arm64e 设备、TrollStore 安装 launcher，以及目标
应用版本匹配内置 direct profile。

实现使用以下开源项目并保留许可证：

- `Lessica/TrollFools@1a4d4a301e096092f20c760fb2903c8f4db37240`（MIT）：launcher 的精简
  injector 改写自其 bundle 发现、Mach-O 选择、备份和 CoreTrust 流程，并固定校验、打包该
  提交中的 `ct_bypass`、`insert_dylib` 和 `ldid`。TIPA 内含 `LICENSE.trollfools.txt`。
- `opa334/Dopamine@38f324012407088b00e1c3530c967e00c2310315`（MIT）：跨进程注入能力
  依赖完整 kernel exploit、PAC/PPL 绕过和 bootstrap。它不能作为“仅 TrollStore”后端的
  通用库，因此本项目没有捆绑 Dopamine/KFD。

## 构建

```bash
cd ios
npm ci
npm run build

OPENBACHELOR_DOWNLOAD_PROXY=http://127.0.0.1:20122 \
  launcher/build.sh
```

也可以使用已下载的官方 devkit，避免联网：

```bash
FRIDA_DEVKIT_ARCHIVE=/path/to/frida-core-devkit-17.9.1-ios-arm64.tar.xz \
  launcher/build.sh
```

若官方归档已经解压，也可以直接使用目录；脚本仍会校验 17.9.1 的 header 和静态库哈希：

```bash
FRIDA_DEVKIT_DIR=/path/to/frida-core-devkit-17.9.1-ios-arm64 \
FRIDA_GADGET_ARCHIVE=/path/to/frida-gadget-17.9.1-ios-universal.dylib.xz \
TROLLFOOLS_SOURCE_DIR=/path/to/TrollFools \
  launcher/build.sh
```

默认生成三个产物：

- `launcher/dist/OpenBachelorLauncher.tipa`：推荐直接用 TrollStore 安装；
- `launcher/dist/OpenBachelorLauncher.ipa`：与 TIPA 内容相同；
- `launcher/dist/OpenBachelorGadget-TrollFools.zip`：包含可在 arm64/arm64e 设备运行的 arm64
  Frida Gadget framework，作为手动 TrollFools 注入的兼容/恢复入口。framework 的主程序是
  一个极小 bootstrap；它先让应用完成早期初始化，再延迟加载真正的 Frida runtime，避免
  dyld constructor 阶段的首个信号进入尚未准备好的 Frida 异常后端并递归 `abort`。构建还会
  对固定版本 Gadget 做带原字节校验的兼容补丁：禁用 Gadget 内部 POSIX Exceptor backend，
  并阻止其用 Interceptor 改写 libc `signal`/`sigaction`，避免 Gadget 初始化事务为此暂停全部
  Unity/tersafe 线程。补丁还写入独立 `LC_UUID`，用于从崩溃日志明确区分新旧 payload。

构建脚本会固定校验 Frida devkit、Gadget、TrollFools 归档及每个设备端工具的 SHA-256，
同时检查 profile JSON、编译告警、entitlements、上游 Gadget 双架构输入、arm64 兼容切片
伪签名和产物完整性。

## 仅 TrollStore 使用（无需越狱）

### 自动注入（推荐）

1. 用 TrollStore 安装 `OpenBachelorLauncher.tipa`，无需另外安装 TrollFools。
2. 打开 launcher，保持 `TrollStore Gadget`，点击“自动安装并启动”。
3. launcher 先校验目标 Bundle ID 与内置 profile，然后以 root persona 停止目标 App。
4. injector 只选择 `cryptid == 0`、已被目标加载的 embedded framework/dylib，优先避开
   `UnityFramework` 这类大型且常被完整性检查的核心映像，创建 `.openbachelor-gadget.bak`，
   插入弱依赖 Gadget load command，再执行伪签名/CoreTrust 处理。
5. 任一步骤失败都会尝试原子恢复备份；成功后 launcher 唤起目标，连接本机 Gadget 并加载
   direct agent。bootstrap 会在两秒后加载 Gadget，Gadget 使用 `on_load=resume`；即使系统
   拒绝自动唤起、需要手动从桌面启动，也不会因等待 helper 而被启动 watchdog 终止。

界面的“安装 / 修复”可独立执行幂等检查，“移除 Gadget”只恢复 Launcher 自己创建的备份。
如果检测到 TrollFools 等外部工具注入且没有 Launcher 备份，会拒绝移除并提示使用原工具。
目标 App 更新后再次点击“自动安装并启动”即可重新注入。
新版还会在安装时自动恢复旧版创建的 `UnityFramework`/强依赖注入，再按上述安全策略重新
注入；对于旧版无签名流程标记的 Launcher 注入，也会从 `.bak` 恢复后重新执行。这样可修复
崩溃日志中 `CODESIGNING / Invalid Page` 所对应的旧版无条件 `ldid -S` 签名问题。

### 手动兼容路径

如果目标没有可安全修改的未加密 framework/dylib，injector 会 fail closed，不会修改加密主
程序。此时可用 `OpenBachelorGadget-TrollFools.zip` 配合 TrollFools，或用仓库的
`patch-ipa` 处理你从自有设备取得的已解密 IPA。

## 越狱 Frida 使用

1. 在 Sileo/Zebra 中安装 Frida 17.9.1，并确保 `frida-server` 已运行。
2. 用 TrollStore 安装 `OpenBachelorLauncher.ipa`。
3. 在 launcher 中选择 `越狱 Frida` 后端。

## 通用操作

1. 填写目标 bundle id，选择“服务重定向”或“本机抓包”。
2. 重定向模式填写目标 URL，例如 `http://192.168.1.20:8443`；本机抓包无需 URL，
   请求元数据和 body 会保存到 `/var/mobile/Library/OpenBachelorLauncher/captured/`。
3. Gadget 后端点“自动安装并启动”；越狱后端点“启动并注入”。Gadget 后端会直接请求系统
   切换到目标 App，不依赖 helper 的首次状态轮询；越狱后端先附加已运行进程，否则尝试
   Frida suspended spawn。若 spawn 被 FrontBoard、锁屏状态或当前运行实例拒绝，launcher
   会回退到系统唤起，helper 重新枚举真实 PID 后继续 attach。若系统仍拒绝自动切换 App，
   可在一分钟内从桌面手动启动目标，helper 子进程会继续附加。
   Gadget 后端会先切换到目标 App 以启动 listener，再完成 attach、脚本加载和恢复；越狱
   Frida 后端会在 attach/spawn 和恢复后切换到目标 App。
4. 状态卡显示 `direct-ready` 才表示 profile 与当前 `UnityFramework` 匹配且 hook 已安装。
   profile UUID 不匹配、agent 初始化失败或 helper 意外退出都会明确显示为错误，不会被误报为
   已启动。

默认启用“游戏内悬浮窗”。direct agent 就绪后，目标 App 内会显示一个可拖动的原生控制台：

- 标题区域可拖动，右上角可收起为 `OB` 浮标，再点浮标恢复；
- 日志区域实时显示模块、hook、请求/响应和异常摘要，不显示请求查询参数或 body；
- “抓包 开/关”只切换当前会话的捕获，“复制”复制当前可见日志，“清空”只清空面板显示；
- 关闭 Launcher 或切回游戏不会中断 helper 会话。停止会话时会先移除悬浮窗再卸载脚本。

helper 使用单实例锁，重复点击启动不会叠加注入。状态目录中的关键文件为：

- `status.json`：当前会话 ID、阶段、PID、更新时间和 `direct-ready` 结果；
- `session.log`：当前会话文本日志，新会话启动前会原子归档到 `logs/session-*.log`；
- `logs/events-*.jsonl`：每个会话独立保存的完整 agent 结构化事件日志；
- `current-config.json`：最近一次启动配置；
- `captured/capture.jsonl` 和 `captured/bodies/`：本机抓包结果。

这些文件位于 `/var/mobile/Library/OpenBachelorLauncher/`。文本日志使用追加写入，异常退出
不会在下一次启动时被覆盖；事件日志在正常停止时显式同步并关闭。悬浮窗的“清空”不会删除
任何磁盘文件。日志与抓包可能包含账号或请求元数据，请只在已授权设备和账号上使用并按需清理。

## “不依赖电脑”的边界

`TrollStore Gadget` 后端不要求越狱、Mac、USB、`iproxy`、Python 控制器、`frida-server`
或单独安装 TrollFools。它依赖 TrollStore 已提供的 CoreTrust/root-persona 能力，不包含新的
内核利用，也不会运行 Dopamine/KFD。自动 injector 不能修改 FairPlay 加密 Mach-O；没有
安全候选时必须使用已解密 IPA 或外部兼容路径。
